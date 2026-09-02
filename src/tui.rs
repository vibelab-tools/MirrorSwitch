use std::{
    collections::BTreeSet,
    io::{BufRead, Write},
};

use thiserror::Error;

use crate::{
    detection::DetectionReport,
    frontend::{
        ExecutionPreview, FrontendError, FrontendSource, NormalizedRequest, RequestInput,
        normalize_request,
    },
};

pub fn select_tools(
    report: &DetectionReport,
    base: &RequestInput,
    input: &mut dyn BufRead,
    output: &mut dyn Write,
) -> Result<Option<NormalizedRequest>, TuiError> {
    let initial = normalize_request(report, base, FrontendSource::Tui)?;
    let mut selected = initial
        .tools
        .iter()
        .map(|tool| tool.adapter_key.clone())
        .collect::<BTreeSet<_>>();
    writeln!(
        output,
        "MirrorSwitch | os={:?} distribution={} architecture={:?} environment={:?}",
        report.context.os,
        report
            .context
            .distribution
            .as_ref()
            .map_or("unknown", |distribution| distribution.id.as_str()),
        report.context.architecture,
        report.context.environment
    )?;
    writeln!(output, "Detected tools (defaults are checked):")?;
    for (index, item) in report.selections.iter().enumerate() {
        writeln!(
            output,
            "{:>3}. [{}] {:<24} scope={:?} reason={:?}",
            index + 1,
            if selected.contains(&item.adapter_key) {
                "x"
            } else {
                " "
            },
            item.adapter_key,
            item.scope,
            item.reason
        )?;
    }
    if !report.notices.is_empty() {
        writeln!(output, "Skipped/unavailable:")?;
        for notice in &report.notices {
            writeln!(
                output,
                "  - {} [{:?}]: {}",
                notice.subject, notice.code, notice.message
            )?;
        }
    }
    writeln!(
        output,
        "Enter comma-separated numbers to toggle, 'a' for all, 'n' for none, Enter to continue, or 'q' to quit:"
    )?;
    output.flush()?;
    let mut line = String::new();
    input.read_line(&mut line)?;
    match line.trim() {
        "q" | "quit" => return Ok(None),
        "a" | "all" => {
            selected = report
                .selections
                .iter()
                .map(|item| item.adapter_key.clone())
                .collect();
        }
        "n" | "none" => selected.clear(),
        "" => {}
        values => {
            for value in values.split(',') {
                let index = value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| TuiError::InvalidSelection(value.trim().into()))?;
                let item = report
                    .selections
                    .get(
                        index
                            .checked_sub(1)
                            .ok_or_else(|| TuiError::InvalidSelection(value.trim().into()))?,
                    )
                    .ok_or_else(|| TuiError::InvalidSelection(value.trim().into()))?;
                if !selected.remove(&item.adapter_key) {
                    selected.insert(item.adapter_key.clone());
                }
            }
        }
    }
    let mut request = base.clone();
    request.all = false;
    request.categories.clear();
    request.disabled_tools.clear();
    request.tools = selected;
    if request.tools.is_empty() {
        return Ok(Some(NormalizedRequest {
            source: FrontendSource::Tui,
            tools: Vec::new(),
        }));
    }
    normalize_request(report, &request, FrontendSource::Tui)
        .map(Some)
        .map_err(Into::into)
}

pub fn render_preview(preview: &ExecutionPreview, output: &mut dyn Write) -> std::io::Result<()> {
    writeln!(
        output,
        "Plan | architecture={:?} environment={:?}",
        preview.context.architecture, preview.context.environment
    )?;
    for tool in &preview.tools {
        writeln!(output, "[x] {}", tool.adapter_key)?;
        for selection in &tool.selection.selections {
            writeln!(
                output,
                "    mirror={} latency={}ms candidate={}",
                selection.provider_id, selection.latency_ms, selection.candidate_id
            )?;
        }
        for repository in &tool.selection.repositories {
            writeln!(output, "    upstream={}", repository.upstream_id)?;
            for candidate in &repository.candidates {
                writeln!(
                    output,
                    "      candidate={} provider={} result={:?}",
                    candidate.candidate_id, candidate.provider_id, candidate.evaluation
                )?;
            }
        }
        writeln!(
            output,
            "    scope={:?} elevation={} service={:?}",
            tool.plan.scope, tool.plan.requires_elevation, tool.plan.service_impact
        )?;
        for change in &tool.plan.changes {
            writeln!(
                output,
                "    {} old={} new={} mode={:?} -> {:?}",
                change.target.display(),
                change.old.sha256.as_deref().unwrap_or("missing"),
                change.new.sha256.as_deref().unwrap_or("missing"),
                change.old.mode,
                change.new.mode
            )?;
        }
    }
    for skipped in &preview.skipped {
        writeln!(
            output,
            "[ ] {} skipped: {}",
            skipped.adapter_key, skipped.reason
        )?;
    }
    Ok(())
}

pub fn confirm(input: &mut dyn BufRead, output: &mut dyn Write) -> std::io::Result<bool> {
    write!(output, "Apply this plan? [y/N] ")?;
    output.flush()?;
    let mut answer = String::new();
    input.read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "YES"))
}

#[derive(Debug, Error)]
pub enum TuiError {
    #[error("terminal I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid selection {0}")]
    InvalidSelection(String),
    #[error(transparent)]
    Frontend(#[from] FrontendError),
}
