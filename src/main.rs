use std::path::PathBuf;

use anyhow::{bail, Context as _, Result};
use clap::Parser;

use config_gen::{
    apply_extend, generate_from_subscriptions, load_config, prepend_direct_domains,
    write_config, DEFAULT_DIST, DEFAULT_OUTPUT,
};

/// Generate a mihomo config from subscription URLs or a profile file.
#[derive(Debug, Parser)]
#[command(name = "config-gen", version, about)]
struct Cli {
    /// Comma-separated subscription URLs.
    #[arg(long, value_delimiter = ',', value_name = "URLS")]
    subscriptions: Vec<String>,

    /// Comma-separated domains that should bypass the proxy.
    #[arg(long, value_delimiter = ',', value_name = "DOMAINS")]
    direct_domains: Vec<String>,

    /// YAML config file, or a file with a `url` field to download.
    #[arg(long, conflicts_with = "subscriptions", value_name = "FILE")]
    profile: Option<String>,

    /// JavaScript extend script applied to the config (inline code, not a path).
    #[arg(long, value_name = "JS")]
    extend: Option<String>,

    /// Output directory.
    #[arg(long, default_value = DEFAULT_DIST, value_name = "DIR")]
    dist: PathBuf,

    /// Output file name.
    #[arg(long, default_value = DEFAULT_OUTPUT, value_name = "NAME")]
    output: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let subscriptions = clean(&cli.subscriptions);
    let direct_domains = clean(&cli.direct_domains);

    let mut config = match &cli.profile {
        Some(profile) => {
            let path = PathBuf::from(profile);
            if !path.is_file() {
                bail!("profile file not found: {}", path.display());
            }
            load_config(&path)?
        }
        None if !subscriptions.is_empty() => generate_from_subscriptions(&subscriptions),
        None => bail!("either --subscriptions or --profile is required"),
    };

    prepend_direct_domains(&mut config, &direct_domains)?;

    if let Some(script) = &cli.extend {
        apply_extend(&mut config, script).context("failed to run the extend script")?;
    }

    let path = write_config(&config, &cli.dist, &cli.output)?;
    println!("Config generated successfully: {}", path.display());

    Ok(())
}

fn clean(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}
