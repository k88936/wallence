use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context as _, Result};
use boa_engine::{js_string, Context, JsValue, Source};
use serde_json::{json, Map, Value};

pub const DEFAULT_DIST: &str = "/etc/mihomo/";
pub const DEFAULT_OUTPUT: &str = "config.yaml";

const HEALTH_CHECK_URL: &str = "https://cp.cloudflare.com/generate_204";

/// Builds a mihomo config that loads every subscription through a proxy provider.
pub fn generate_from_subscriptions(subscriptions: &[String]) -> Value {
    let mut providers = Map::new();
    let mut provider_names = Vec::with_capacity(subscriptions.len());

    for (index, subscription) in subscriptions.iter().enumerate() {
        let name = format!("provider{}", index + 1);
        providers.insert(
            name.clone(),
            json!({
                "type": "http",
                "url": format!("{subscription}?group=gfw"),
                "interval": 3600,
                "path": format!("./provider-gfw-{}.yaml", index + 1),
                "health-check": {
                    "enable": true,
                    "interval": 300,
                    "url": HEALTH_CHECK_URL,
                },
            }),
        );
        provider_names.push(Value::String(name));
    }

    json!({
        "mixed-port": 7890,
        "allow-lan": true,
        "mode": "rule",
        "log-level": "info",
        "dns": {
            "enable": true,
            "listen": "0.0.0.0:53",
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "default-nameserver": ["114.114.114.114", "8.8.8.8"],
            "nameserver": ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
        },
        "proxy-providers": providers,
        "proxy-groups": [{
            "name": "LOAD-BALANCE-GROUP",
            "type": "load-balance",
            "url": HEALTH_CHECK_URL,
            "interval": 300,
            "use": provider_names,
        }],
        "rules": [
            "GEOIP,LAN,DIRECT",
            "GEOIP,CN,DIRECT",
            "MATCH,LOAD-BALANCE-GROUP",
        ],
    })
}

/// Loads a config from a YAML file, downloading it when the file only holds a `url`.
pub fn load_config(path: &Path) -> Result<Value> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let source = path.display().to_string();
    let document = parse_yaml(&text, &source)?;

    match document.get("url").and_then(Value::as_str) {
        Some(url) => fetch_config(url),
        None => Ok(document),
    }
}

/// Downloads a config from `url`.
pub fn fetch_config(url: &str) -> Result<Value> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(15))
        .timeout(Duration::from_secs(60))
        .try_proxy_from_env(true)
        .build();
    let response = agent
        .get(url)
        .call()
        .with_context(|| format!("failed to download {url}"))?;
    let text = response
        .into_string()
        .with_context(|| format!("failed to read the response of {url}"))?;

    parse_yaml(&text, url)
}

fn parse_yaml(text: &str, source: &str) -> Result<Value> {
    let yaml: serde_yaml::Value =
        serde_yaml::from_str(text).with_context(|| format!("failed to parse {source} as YAML"))?;
    serde_json::to_value(&yaml)
        .with_context(|| format!("{source} contains values that cannot be represented as JSON"))
}

/// Prepends `DOMAIN-SUFFIX,<domain>,DIRECT` rules to the config, keeping existing rules after them.
pub fn prepend_direct_domains(config: &mut Value, domains: &[String]) -> Result<()> {
    if domains.is_empty() {
        return Ok(());
    }

    let rules = domains
        .iter()
        .map(|domain| Value::String(format!("DOMAIN-SUFFIX,{domain},DIRECT")))
        .collect();
    prepend_rules(config, rules)
}

/// Runs an `extend.js` style script against the config.
///
/// The script must define `function main(config)` and return the modified config. Execution
/// happens in a sandboxed JavaScript engine (no host objects are exposed).
pub fn apply_extend(config: &mut Value, script: &str) -> Result<()> {
    // Scripts commonly prepend to `config.rules`, so make sure the list always exists.
    let object = config
        .as_object_mut()
        .context("the config must be a YAML mapping")?;
    if matches!(object.get("rules"), None | Some(Value::Null)) {
        object.insert("rules".to_owned(), Value::Array(Vec::new()));
    }

    let mut context = Context::default();
    js_result(
        context.eval(Source::from_bytes(script)),
        "failed to evaluate the extend script",
    )?;

    let main = js_result(
        context
            .global_object()
            .get(js_string!("main"), &mut context),
        "failed to read the extend script's main function",
    )?;
    let Some(main) = main.as_callable() else {
        bail!("the extend script must define a callable main(config) function");
    };

    let js_config = js_result(
        JsValue::from_json(config, &mut context),
        "failed to pass the config to the extend script",
    )?;
    let result = js_result(
        main.call(&JsValue::undefined(), &[js_config], &mut context),
        "the extend script's main(config) threw an exception",
    )?;

    let Some(updated) = js_result(
        result.to_json(&mut context),
        "the extend script's main(config) returned a value that cannot be converted to YAML",
    )?
    else {
        bail!("the extend script's main(config) must return the config object");
    };

    *config = updated;
    Ok(())
}

/// Serializes the config as YAML into `dist/name` and returns the written path.
pub fn write_config(config: &Value, dist: &Path, name: &str) -> Result<PathBuf> {
    let yaml = serde_yaml::to_string(config).context("failed to serialize the config as YAML")?;

    fs::create_dir_all(dist)
        .with_context(|| format!("failed to create output directory {}", dist.display()))?;
    let path = dist.join(name);
    fs::write(&path, yaml).with_context(|| format!("failed to write {}", path.display()))?;

    Ok(path)
}

fn js_result<T>(result: Result<T, boa_engine::JsError>, message: &str) -> Result<T> {
    result.map_err(|error| anyhow!("{message}: {error}"))
}

fn prepend_rules(config: &mut Value, rules: Vec<Value>) -> Result<()> {
    let object = config
        .as_object_mut()
        .context("the config must be a YAML mapping")?;
    let rules_value = object
        .entry("rules")
        .or_insert_with(|| Value::Array(Vec::new()));
    let existing = rules_value
        .as_array_mut()
        .context("the config's 'rules' field must be a list")?;

    let mut merged = rules;
    merged.append(existing);
    *existing = merged;

    Ok(())
}
