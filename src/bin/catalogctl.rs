use std::{env, fs, path::PathBuf, process::ExitCode};

use mirrorswitch::{
    MirrorCatalog,
    adapters::compiled_adapter_allowlist,
    catalog_update::{CatalogUpdater, EMBEDDED_CATALOG},
};
use serde_json::json;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("catalogctl: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1);
    match arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .as_deref()
    {
        Some("validate") => {
            let path = arguments.next().map(PathBuf::from);
            if arguments.next().is_some() {
                return Err("usage: catalogctl validate [catalog-path]".into());
            }
            let bytes = match path {
                Some(path) => fs::read(path)?,
                None => EMBEDDED_CATALOG.to_vec(),
            };
            let catalog: MirrorCatalog = serde_json::from_slice(&bytes)?;
            catalog.validate(&compiled_adapter_allowlist())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "valid": true,
                    "schema_version": catalog.schema_version,
                    "content_version": catalog.content_version,
                    "content_revision": catalog.content_revision,
                    "generated_at": catalog.generated_at,
                    "providers": catalog.providers.len(),
                    "tools": catalog.tools.len(),
                    "candidates": catalog.candidates.len(),
                }))?
            );
        }
        Some("status" | "update") => {
            let cache_path = arguments
                .next()
                .map(PathBuf::from)
                .ok_or("usage: catalogctl status <cache-path>")?;
            if arguments.next().is_some() {
                return Err("usage: catalogctl status <cache-path>".into());
            }
            let loaded = CatalogUpdater::new(cache_path).load(&compiled_adapter_allowlist())?;
            println!("{}", serde_json::to_string_pretty(&loaded.status)?);
        }
        _ => {
            return Err("usage: catalogctl <validate [catalog-path] | status <cache-path>>".into());
        }
    }
    Ok(())
}
