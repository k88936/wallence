use std::collections::HashSet;
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

/// Merges rules and proxy groups from full subscription profiles into a provider-based config.
///
/// A `proxy-provider` only contributes proxies. To preserve a subscription's own routing, the
/// complete profile must be supplied separately. Fixed proxy names in its groups are replaced by
/// the config's providers so the groups keep working with dynamically updated nodes.
pub fn apply_rule_sources(config: &mut Value, sources: &[Value]) -> Result<()> {
    let (provider_names, mut seen_groups) = {
        let object = config
            .as_object()
            .context("the config must be a YAML mapping")?;
        let providers = object
            .get("proxy-providers")
            .and_then(Value::as_object)
            .context("the config's 'proxy-providers' field must be a mapping")?;
        let provider_names = providers.keys().cloned().collect::<Vec<_>>();
        let seen_groups = object
            .get("proxy-groups")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|group| group.get("name").and_then(Value::as_str))
            .map(str::to_owned)
            .collect::<HashSet<_>>();
        (provider_names, seen_groups)
    };

    let mut merged_rules = Vec::new();
    let mut seen_rules = HashSet::new();
    let mut merged_groups = Vec::new();
    let mut merged_rule_providers = Map::new();

    for source in sources {
        let object = source
            .as_object()
            .context("a rule source must be a YAML mapping")?;
        let source_proxy_names = object
            .get("proxies")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|proxy| proxy.get("name").and_then(Value::as_str))
            .map(str::to_owned)
            .collect::<HashSet<_>>();

        let rules = object
            .get("rules")
            .and_then(Value::as_array)
            .with_context(|| "a rule source must contain a 'rules' list")?;
        for rule in rules {
            let rule = rule
                .as_str()
                .context("every entry in a rule source's 'rules' list must be a string")?;
            if seen_rules.insert(rule.to_owned()) {
                merged_rules.push(Value::String(rule.to_owned()));
            }
        }

        if let Some(groups) = object.get("proxy-groups").and_then(Value::as_array) {
            for group in groups {
                let mut group = group.clone();
                let group_object = group
                    .as_object_mut()
                    .context("every proxy group must be a mapping")?;
                let name = group_object
                    .get("name")
                    .and_then(Value::as_str)
                    .context("every proxy group must have a name")?
                    .to_owned();
                if !seen_groups.insert(name) {
                    continue;
                }

                let mut uses_provider = false;
                let mut remove_empty_proxies = false;
                if let Some(proxies) = group_object
                    .get_mut("proxies")
                    .and_then(Value::as_array_mut)
                {
                    let original_len = proxies.len();
                    proxies.retain(|proxy| {
                        proxy
                            .as_str()
                            .map_or(true, |name| !source_proxy_names.contains(name))
                    });
                    uses_provider = proxies.len() != original_len;
                    remove_empty_proxies = proxies.is_empty();
                }
                if remove_empty_proxies {
                    group_object.remove("proxies");
                }
                if uses_provider {
                    let use_value = group_object
                        .entry("use")
                        .or_insert_with(|| Value::Array(Vec::new()));
                    let use_list = use_value
                        .as_array_mut()
                        .context("a proxy group's 'use' field must be a list")?;
                    for provider in &provider_names {
                        let provider = Value::String(provider.clone());
                        if !use_list.contains(&provider) {
                            use_list.push(provider);
                        }
                    }
                }

                merged_groups.push(group);
            }
        }

        if let Some(rule_providers) = object.get("rule-providers").and_then(Value::as_object) {
            for (name, provider) in rule_providers {
                merged_rule_providers
                    .entry(name.clone())
                    .or_insert_with(|| provider.clone());
            }
        }
    }

    if merged_rules.is_empty() {
        bail!("the supplied rule sources contain no rules");
    }

    let object = config
        .as_object_mut()
        .context("the config must be a YAML mapping")?;
    object.insert("rules".to_owned(), Value::Array(merged_rules));

    let groups_value = object
        .entry("proxy-groups")
        .or_insert_with(|| Value::Array(Vec::new()));
    groups_value
        .as_array_mut()
        .context("the config's 'proxy-groups' field must be a list")?
        .extend(merged_groups);

    if !merged_rule_providers.is_empty() {
        let providers_value = object
            .entry("rule-providers")
            .or_insert_with(|| Value::Object(Map::new()));
        let providers = providers_value
            .as_object_mut()
            .context("the config's 'rule-providers' field must be a mapping")?;
        for (name, provider) in merged_rule_providers {
            providers.entry(name).or_insert(provider);
        }
    }

    Ok(())
}

/// Loads a config from a YAML file, downloading it when the file only holds a `url`.
pub fn load_config(path: &Path) -> Result<Value> {
    let text =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_rules_and_makes_provider_groups_dynamic() {
        let mut config = generate_from_subscriptions(&[
            "https://example.com/sub-a".to_owned(),
            "https://example.com/sub-b".to_owned(),
        ]);
        let source = json!({
            "proxies": [{"name": "node-a"}, {"name": "node-b"}],
            "proxy-groups": [
                {"name": "GFW", "type": "select", "proxies": ["node-a", "node-b"]},
                {"name": "Accel", "type": "select", "proxies": ["DIRECT", "GFW"]}
            ],
            "rule-providers": {
                "ads": {
                    "type": "http",
                    "url": "https://example.com/ads.yaml",
                    "path": "./ads.yaml",
                    "behavior": "domain"
                }
            },
            "rules": [
                "DOMAIN-SUFFIX,example.com,GFW",
                "GEOIP,CN,DIRECT",
                "MATCH,DIRECT"
            ]
        });

        apply_rule_sources(&mut config, &[source]).unwrap();

        assert_eq!(
            config["rules"],
            json!([
                "DOMAIN-SUFFIX,example.com,GFW",
                "GEOIP,CN,DIRECT",
                "MATCH,DIRECT"
            ])
        );
        let groups = config["proxy-groups"].as_array().unwrap();
        let gfw = groups.iter().find(|group| group["name"] == "GFW").unwrap();
        assert!(gfw.get("proxies").is_none());
        assert_eq!(gfw["use"], json!(["provider1", "provider2"]));

        let accel = groups
            .iter()
            .find(|group| group["name"] == "Accel")
            .unwrap();
        assert_eq!(accel["proxies"], json!(["DIRECT", "GFW"]));
        assert!(accel.get("use").is_none());
        assert_eq!(config["rule-providers"]["ads"]["path"], "./ads.yaml");
    }

    #[test]
    fn ignores_duplicate_rules_and_groups_from_multiple_sources() {
        let mut config = generate_from_subscriptions(&["https://example.com/sub".to_owned()]);
        let source = json!({
            "proxies": [{"name": "node"}],
            "proxy-groups": [{"name": "GFW", "type": "select", "proxies": ["node"]}],
            "rules": ["DOMAIN-SUFFIX,example.com,GFW", "MATCH,DIRECT"]
        });

        apply_rule_sources(&mut config, &[source.clone(), source]).unwrap();

        assert_eq!(config["rules"].as_array().unwrap().len(), 2);
        assert_eq!(
            config["proxy-groups"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|group| group["name"] == "GFW")
                .count(),
            1
        );
    }
}
