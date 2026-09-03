use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Output,
};

use thiserror::Error;

use crate::{
    catalog::{CompositionPolicy, ConfigurationScope},
    context::SystemContext,
    plan::{
        ChangePlan, CurrentConfiguration, DetectedTool, MirrorSelection, RestoreResult,
        VerificationResult,
    },
    selection::SelectionRequest,
    transaction::{ApplyOutcome, RestoreReceipt, TransactionReceipt},
};

/// Narrow access to the host. Concrete filesystem and process behavior is
/// implemented by the transaction/runtime issue, while adapters remain
/// testable against controlled roots.
pub trait Runtime {
    fn command_exists(&self, command: &str) -> bool;
    fn home_dir(&self) -> Option<PathBuf> {
        None
    }
    fn project_dir(&self) -> Option<PathBuf> {
        None
    }
    fn environment_variable(&self, _name: &str) -> Option<String> {
        None
    }
    fn read(&self, path: &Path) -> Result<Option<Vec<u8>>, AdapterError>;
    fn list_files(&self, directory: &Path) -> Result<Vec<PathBuf>, AdapterError> {
        Err(AdapterError::Unsupported(format!(
            "directory listing is unavailable for {}",
            directory.display()
        )))
    }
    fn run(&self, program: &str, arguments: &[String]) -> Result<Output, AdapterError>;
    fn run_in(
        &self,
        _directory: &Path,
        program: &str,
        arguments: &[String],
    ) -> Result<Output, AdapterError> {
        self.run(program, arguments)
    }
    fn run_in_with_environment(
        &self,
        _directory: &Path,
        _program: &str,
        _arguments: &[String],
        _environment: &BTreeMap<String, String>,
        _removed_environment: &[String],
    ) -> Result<Output, AdapterError> {
        Err(AdapterError::Unsupported(
            "native per-command environment isolation is unavailable in this runtime".into(),
        ))
    }
    fn run_with_environment(
        &self,
        _program: &str,
        _arguments: &[String],
        _environment: &BTreeMap<String, String>,
        _removed_environment: &[String],
    ) -> Result<Output, AdapterError> {
        Err(AdapterError::Unsupported(
            "native per-command environment isolation is unavailable in this runtime".into(),
        ))
    }
    fn apply_plan(&mut self, _plan: &ChangePlan) -> Result<ApplyOutcome, AdapterError> {
        Err(AdapterError::Unsupported(
            "transaction apply is unavailable in this runtime".into(),
        ))
    }
    fn restore_transaction(
        &mut self,
        _transaction_id: &str,
    ) -> Result<RestoreReceipt, AdapterError> {
        Err(AdapterError::Unsupported(
            "transaction restore is unavailable in this runtime".into(),
        ))
    }
    fn transaction_receipt(
        &self,
        _transaction_id: &str,
    ) -> Result<TransactionReceipt, AdapterError> {
        Err(AdapterError::Unsupported(
            "transaction inspection is unavailable in this runtime".into(),
        ))
    }
}

/// Contract implemented by every tool adapter compiled into MirrorSwitch.
///
/// Catalog data may refer to `adapter_key`, but only objects registered by the
/// binary can implement these operations.
pub trait Adapter: Send + Sync {
    fn key(&self) -> &'static str;
    fn tool_id(&self) -> &'static str;
    fn supported_scopes(&self) -> &'static [ConfigurationScope];
    fn default_scope(&self) -> ConfigurationScope;
    fn default_scope_for(
        &self,
        _context: &SystemContext,
        _runtime: &dyn Runtime,
        _detected: &DetectedTool,
    ) -> Result<ConfigurationScope, AdapterError> {
        Ok(self.default_scope())
    }
    fn composition_policy(&self) -> CompositionPolicy;

    fn detect(
        &self,
        context: &SystemContext,
        runtime: &dyn Runtime,
    ) -> Result<Option<DetectedTool>, AdapterError>;

    fn read_current(
        &self,
        context: &SystemContext,
        runtime: &dyn Runtime,
        detected: &DetectedTool,
        scope: ConfigurationScope,
    ) -> Result<CurrentConfiguration, AdapterError>;

    fn plan(
        &self,
        context: &SystemContext,
        current: &CurrentConfiguration,
        selection: &[MirrorSelection],
    ) -> Result<ChangePlan, AdapterError>;

    fn selection_request(
        &self,
        _context: &SystemContext,
        _detected: &DetectedTool,
        _current: &CurrentConfiguration,
    ) -> Result<SelectionRequest, AdapterError> {
        Err(AdapterError::Unsupported(
            "adapter does not provide mirror-selection requirements".into(),
        ))
    }

    fn apply(
        &self,
        context: &SystemContext,
        runtime: &mut dyn Runtime,
        plan: &ChangePlan,
    ) -> Result<ApplyOutcome, AdapterError>;

    fn verify(
        &self,
        context: &SystemContext,
        runtime: &mut dyn Runtime,
        receipt: &TransactionReceipt,
    ) -> Result<VerificationResult, AdapterError>;

    fn restore(
        &self,
        context: &SystemContext,
        runtime: &mut dyn Runtime,
        receipt: &TransactionReceipt,
    ) -> Result<RestoreResult, AdapterError>;
}

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("the current context is unsupported: {0}")]
    Unsupported(String),
    #[error("the current configuration is invalid: {0}")]
    InvalidConfiguration(String),
    #[error("permission denied while reading configuration: {0}")]
    PermissionDenied(String),
    #[error("the planned state no longer matches the target: {0}")]
    Conflict(String),
    #[error("runtime operation failed: {0}")]
    Runtime(String),
    #[error("post-apply verification failed: {0}")]
    Verification(String),
}
