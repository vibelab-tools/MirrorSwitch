use std::{
    env,
    io::{self, BufReader, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use mirrorswitch::{
    MirrorCatalog, Runtime,
    adapters::{compiled_adapter_allowlist, compiled_adapters},
    catalog::ConfigurationScope,
    catalog_update::{CatalogUpdater, EMBEDDED_CATALOG},
    detection::{LinuxDetectionOptions, OsRuntime, detect_linux},
    frontend::{
        FrontendSource, RequestInput, apply_detection_overrides, apply_execution,
        load_configuration, normalize_request, prepare_execution,
    },
    selection::HttpCandidateProber,
    tui,
};
use serde::Serialize;
use serde_json::json;

const HELP: &str = "MirrorSwitch 0.1.0

Usage:
  mirrorswitch detect [OPTIONS]
  mirrorswitch plan [OPTIONS]
  mirrorswitch apply --yes [OPTIONS]
  mirrorswitch status [--offline] [--json]
  mirrorswitch restore TRANSACTION_ID --yes [--json]
  mirrorswitch tui [OPTIONS]

Options:
  --all                         Select every detected tool
  --tool ID                     Select one adapter (repeatable)
  --disable ID                  Deselect one adapter (repeatable)
  --category NAME               system|language|container|infrastructure
  --scope TOOL=system|user      Override a detected tool scope
  --mirror TOOL:UPSTREAM=ID     Use one reviewed candidate ID
  --config PATH                 Read a version 1 JSON configuration
  --offline                     Use the embedded catalog without Raw update
  --json                        Emit stable JSON
  --yes                         Explicitly authorize apply/restore
  -h, --help                    Show help
  -V, --version                 Show version

Exit codes: 0 success, 2 usage/configuration error, 3 no actionable plan or partial apply.
";

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            if error.json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({"ok": false, "error": error.message})).unwrap()
                );
            } else {
                eprintln!("mirrorswitch: {}", error.message);
            }
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<u8, CliError> {
    let parsed = parse_arguments(env::args().skip(1))?;
    if parsed.help {
        print!("{HELP}");
        return Ok(0);
    }
    if parsed.version {
        println!("mirrorswitch {}", env!("CARGO_PKG_VERSION"));
        return Ok(0);
    }
    let command = parsed
        .command
        .as_deref()
        .ok_or_else(|| usage(&parsed, "missing command"))?;
    if command == "restore" {
        return restore(&parsed);
    }
    if command == "apply" && !parsed.yes {
        return Err(usage(&parsed, "apply requires --yes"));
    }

    let options = LinuxDetectionOptions::current();
    let adapters = compiled_adapters();
    let mut report = detect_linux(&options, &adapters).map_err(|error| cli(&parsed, error))?;
    let (catalog, catalog_status) = load_catalog(&parsed, &options.home)?;
    let mut input = match &parsed.config {
        Some(path) => load_configuration(path).map_err(|error| cli(&parsed, error))?,
        None => RequestInput::default(),
    };
    input.merge(parsed.input.clone());
    let source = if parsed.config.is_some() && !parsed.has_cli_selection {
        FrontendSource::Configuration
    } else {
        FrontendSource::Cli
    };

    if command == "status" {
        return output(
            &parsed,
            &json!({
                "ok": true,
                "command": "status",
                "catalog": catalog_status,
                "context": report.context,
                "container": report.container,
                "permissions": report.permissions,
                "detected_tools": report.tools,
                "selections": report.selections,
                "notices": report.notices,
            }),
        );
    }

    if command == "detect" {
        let request =
            normalize_request(&report, &input, source).map_err(|error| cli(&parsed, error))?;
        apply_detection_overrides(&mut report, &request);
        return output(
            &parsed,
            &json!({"ok": true, "command": "detect", "catalog": catalog_status, "request": request, "report": report}),
        );
    }

    let request = if command == "tui" {
        let stdin = io::stdin();
        let mut reader = BufReader::new(stdin.lock());
        let mut stdout = io::stdout();
        match tui::select_tools(&report, &input, &mut reader, &mut stdout)
            .map_err(|error| cli(&parsed, error))?
        {
            Some(request) => request,
            None => return Ok(0),
        }
    } else {
        normalize_request(&report, &input, source).map_err(|error| cli(&parsed, error))?
    };
    let mut runtime = runtime(&options);
    let prepared = prepare_execution(&report, &request, &catalog, &adapters, HttpCandidateProber)
        .map_err(|error| cli(&parsed, error))?;
    let preview = prepared.preview();

    if command == "plan" {
        let actionable = !prepared.tools.is_empty();
        output(
            &parsed,
            &json!({"ok": actionable, "command": "plan", "catalog": catalog_status, "request": request, "plan": preview}),
        )?;
        return Ok(if actionable { 0 } else { 3 });
    }
    if command == "tui" {
        let mut stdout = io::stdout();
        tui::render_preview(&preview, &mut stdout).map_err(|error| cli(&parsed, error))?;
        if !parsed.yes && !confirm(&mut stdout).map_err(|error| cli(&parsed, error))? {
            return Ok(0);
        }
    } else if command != "apply" {
        return Err(usage(&parsed, "unknown command"));
    }
    if prepared.tools.is_empty() {
        output(
            &parsed,
            &json!({"ok": false, "command": command, "catalog": catalog_status, "request": request, "plan": preview}),
        )?;
        return Ok(3);
    }
    let applied = apply_execution(prepared, &adapters, &mut runtime);
    let code = if applied.successful { 0 } else { 3 };
    output(
        &parsed,
        &json!({"ok": applied.successful, "command": command, "catalog": catalog_status, "result": applied}),
    )?;
    Ok(code)
}

fn confirm(output: &mut dyn Write) -> io::Result<bool> {
    write!(output, "Apply this plan? [y/N] ")?;
    output.flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "YES"))
}

fn runtime(options: &LinuxDetectionOptions) -> OsRuntime {
    let mut runtime = OsRuntime::new(&options.root, options.executable_path.clone())
        .with_home(options.home.clone());
    if let Some(project) = &options.project_dir {
        runtime = runtime.with_project_dir(project.clone());
    }
    runtime
}

fn load_catalog(
    parsed: &Arguments,
    home: &Path,
) -> Result<(MirrorCatalog, serde_json::Value), CliError> {
    if parsed.offline {
        let catalog: MirrorCatalog =
            serde_json::from_slice(EMBEDDED_CATALOG).map_err(|error| cli(parsed, error))?;
        catalog
            .validate(&compiled_adapter_allowlist())
            .map_err(|error| cli(parsed, error))?;
        let status = json!({
            "schema_version": catalog.schema_version,
            "content_version": catalog.content_version,
            "content_revision": catalog.content_revision,
            "generated_at": catalog.generated_at,
            "source": "embedded-baseline",
            "update": {"status": "offline"},
        });
        return Ok((catalog, status));
    }
    let cache = env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".cache"))
        .join("mirrorswitch/catalog.json");
    let loaded = CatalogUpdater::new(cache)
        .load(&compiled_adapter_allowlist())
        .map_err(|error| cli(parsed, error))?;
    let status = serde_json::to_value(&loaded.status).map_err(|error| cli(parsed, error))?;
    Ok((loaded.catalog, status))
}

fn restore(parsed: &Arguments) -> Result<u8, CliError> {
    if !parsed.yes {
        return Err(usage(parsed, "restore requires --yes"));
    }
    let id = parsed
        .positionals
        .first()
        .ok_or_else(|| usage(parsed, "restore requires a transaction ID"))?;
    if parsed.positionals.len() != 1 {
        return Err(usage(parsed, "restore accepts one transaction ID"));
    }
    let options = LinuxDetectionOptions::current();
    let mut runtime = runtime(&options);
    let receipt = runtime
        .restore_transaction(id)
        .map_err(|error| cli(parsed, error))?;
    output(
        parsed,
        &json!({"ok": receipt.verified, "command": "restore", "receipt": receipt}),
    )?;
    Ok(if receipt.verified { 0 } else { 3 })
}

fn output<T: Serialize>(parsed: &Arguments, value: &T) -> Result<u8, CliError> {
    let serialized = if parsed.json {
        serde_json::to_string(value)
    } else {
        serde_json::to_string_pretty(value)
    }
    .map_err(|error| cli(parsed, error))?;
    println!("{serialized}");
    Ok(0)
}

#[derive(Clone, Debug, Default)]
struct Arguments {
    command: Option<String>,
    positionals: Vec<String>,
    input: RequestInput,
    config: Option<PathBuf>,
    offline: bool,
    json: bool,
    yes: bool,
    help: bool,
    version: bool,
    has_cli_selection: bool,
}

fn parse_arguments(arguments: impl Iterator<Item = String>) -> Result<Arguments, CliError> {
    let mut parsed = Arguments::default();
    let mut values = arguments.peekable();
    while let Some(value) = values.next() {
        match value.as_str() {
            "-h" | "--help" => parsed.help = true,
            "-V" | "--version" => parsed.version = true,
            "--offline" => parsed.offline = true,
            "--json" => parsed.json = true,
            "--yes" => parsed.yes = true,
            "--all" => {
                parsed.input.all = true;
                parsed.has_cli_selection = true;
            }
            "--tool" | "--disable" | "--category" | "--scope" | "--mirror" | "--config" => {
                let item = values.next().ok_or_else(|| CliError {
                    json: parsed.json,
                    message: format!("{value} requires a value"),
                })?;
                match value.as_str() {
                    "--tool" => {
                        parsed.input.tools.insert(item);
                        parsed.has_cli_selection = true;
                    }
                    "--disable" => {
                        parsed.input.disabled_tools.insert(item);
                        parsed.has_cli_selection = true;
                    }
                    "--category" => {
                        parsed.input.categories.insert(item);
                        parsed.has_cli_selection = true;
                    }
                    "--scope" => {
                        let (tool, scope) = split_once(&parsed, &item, '=')?;
                        parsed
                            .input
                            .scopes
                            .insert(tool.into(), parse_scope(&parsed, scope)?);
                        parsed.has_cli_selection = true;
                    }
                    "--mirror" => {
                        let (tool_upstream, candidate) = split_once(&parsed, &item, '=')?;
                        let (tool, upstream) = split_once(&parsed, tool_upstream, ':')?;
                        parsed
                            .input
                            .overrides
                            .entry(tool.into())
                            .or_default()
                            .insert(upstream.into(), candidate.into());
                        parsed.has_cli_selection = true;
                    }
                    "--config" => parsed.config = Some(item.into()),
                    _ => unreachable!(),
                }
            }
            option if option.starts_with('-') => {
                return Err(usage(&parsed, &format!("unknown option {option}")));
            }
            _ if parsed.command.is_none() => parsed.command = Some(value),
            _ => parsed.positionals.push(value),
        }
    }
    Ok(parsed)
}

fn parse_scope(parsed: &Arguments, value: &str) -> Result<ConfigurationScope, CliError> {
    match value {
        "system" => Ok(ConfigurationScope::System),
        "user" => Ok(ConfigurationScope::User),
        "site" => Ok(ConfigurationScope::Site),
        "project" => Ok(ConfigurationScope::Project),
        "environment" => Ok(ConfigurationScope::Environment),
        _ => Err(usage(parsed, "unknown scope")),
    }
}

fn split_once<'a>(
    parsed: &Arguments,
    value: &'a str,
    separator: char,
) -> Result<(&'a str, &'a str), CliError> {
    value
        .split_once(separator)
        .filter(|(left, right)| !left.is_empty() && !right.is_empty())
        .ok_or_else(|| usage(parsed, &format!("invalid value {value}")))
}

fn usage(parsed: &Arguments, message: &str) -> CliError {
    CliError {
        json: parsed.json,
        message: format!("{message}; use --help"),
    }
}

fn cli(parsed: &Arguments, error: impl std::fmt::Display) -> CliError {
    CliError {
        json: parsed.json,
        message: error.to_string(),
    }
}

#[derive(Debug)]
struct CliError {
    json: bool,
    message: String,
}
