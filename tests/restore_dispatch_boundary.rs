use std::{
    cell::{Cell, RefCell},
    path::{Path, PathBuf},
    process::Output,
};

use mirrorswitch::{
    Adapter, AdapterError, Runtime,
    catalog::{CompositionPolicy, ConfigurationScope},
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    frontend::{FrontendError, restore_execution},
    plan::{
        ChangePlan, CurrentConfiguration, DetectedTool, MirrorSelection, RestoreResult,
        VerificationResult,
    },
    selection::SelectionRequest,
    transaction::{ApplyOutcome, RestoreReceipt, TransactionParticipant, TransactionReceipt},
};

struct DispatchRuntime {
    receipt: TransactionReceipt,
    state_present: Cell<bool>,
    operations: RefCell<Vec<&'static str>>,
}

impl Runtime for DispatchRuntime {
    fn command_exists(&self, _command: &str) -> bool {
        false
    }

    fn read(&self, path: &Path) -> Result<Option<Vec<u8>>, AdapterError> {
        if path == Path::new("/private-command-state") {
            self.operations.borrow_mut().push("read-state");
            Ok(self.state_present.get().then(|| b"state".to_vec()))
        } else {
            Ok(None)
        }
    }

    fn run(&self, _program: &str, _arguments: &[String]) -> Result<Output, AdapterError> {
        Err(AdapterError::Unsupported("not used".into()))
    }

    fn transaction_receipt(
        &self,
        transaction_id: &str,
    ) -> Result<TransactionReceipt, AdapterError> {
        self.operations.borrow_mut().push("inspect-receipt");
        if transaction_id == self.receipt.transaction_id && self.state_present.get() {
            Ok(self.receipt.clone())
        } else {
            Err(AdapterError::Runtime("transaction is not applied".into()))
        }
    }

    fn restore_transaction(
        &mut self,
        transaction_id: &str,
    ) -> Result<RestoreReceipt, AdapterError> {
        self.operations.get_mut().push("restore-files");
        if transaction_id != self.receipt.transaction_id || !self.state_present.replace(false) {
            return Err(AdapterError::Runtime("transaction is not applied".into()));
        }
        Ok(RestoreReceipt {
            transaction_id: transaction_id.into(),
            restored_files: self.receipt.changed_files,
            verified: true,
        })
    }
}

#[derive(Clone, Copy)]
struct CommandStateAdapter;

impl Adapter for CommandStateAdapter {
    fn key(&self) -> &'static str {
        "command-state"
    }

    fn tool_id(&self) -> &'static str {
        "command-state"
    }

    fn supported_scopes(&self) -> &'static [ConfigurationScope] {
        &[ConfigurationScope::System]
    }

    fn default_scope(&self) -> ConfigurationScope {
        ConfigurationScope::System
    }

    fn composition_policy(&self) -> CompositionPolicy {
        CompositionPolicy::Single
    }

    fn detect(
        &self,
        _context: &SystemContext,
        _runtime: &dyn Runtime,
    ) -> Result<Option<DetectedTool>, AdapterError> {
        unreachable!()
    }

    fn read_current(
        &self,
        _context: &SystemContext,
        _runtime: &dyn Runtime,
        _detected: &DetectedTool,
        _scope: ConfigurationScope,
    ) -> Result<CurrentConfiguration, AdapterError> {
        unreachable!()
    }

    fn plan(
        &self,
        _context: &SystemContext,
        _current: &CurrentConfiguration,
        _selection: &[MirrorSelection],
    ) -> Result<ChangePlan, AdapterError> {
        unreachable!()
    }

    fn selection_request(
        &self,
        _context: &SystemContext,
        _detected: &DetectedTool,
        _current: &CurrentConfiguration,
    ) -> Result<SelectionRequest, AdapterError> {
        unreachable!()
    }

    fn apply(
        &self,
        _context: &SystemContext,
        _runtime: &mut dyn Runtime,
        _plan: &ChangePlan,
    ) -> Result<ApplyOutcome, AdapterError> {
        unreachable!()
    }

    fn verify(
        &self,
        _context: &SystemContext,
        _runtime: &mut dyn Runtime,
        _receipt: &TransactionReceipt,
    ) -> Result<VerificationResult, AdapterError> {
        unreachable!()
    }

    fn restore(
        &self,
        _context: &SystemContext,
        runtime: &mut dyn Runtime,
        receipt: &TransactionReceipt,
    ) -> Result<RestoreResult, AdapterError> {
        if runtime.read(Path::new("/private-command-state"))?.is_none() {
            return Err(AdapterError::Runtime(
                "command state disappeared before adapter restore".into(),
            ));
        }
        let restored = runtime.restore_transaction(&receipt.transaction_id)?;
        Ok(RestoreResult {
            restored: restored.verified,
            summary: "command state restored before private file rollback".into(),
        })
    }
}

fn context() -> SystemContext {
    SystemContext {
        os: OperatingSystem::Linux,
        architecture: Architecture::X86_64,
        environment: ExecutionEnvironment::Host,
        distribution: Some(Distribution {
            id: "test".into(),
            version_id: None,
            version_codename: None,
            id_like: Vec::new(),
        }),
        root: PathBuf::from("/"),
    }
}

fn receipt(participants: Vec<TransactionParticipant>) -> TransactionReceipt {
    TransactionReceipt {
        transaction_id: "tx-command-state".into(),
        participants,
        changed_files: 1,
        changed_targets: vec![PathBuf::from("/private-command-state")],
    }
}

#[test]
fn explicit_restore_inspects_then_dispatches_adapter_before_file_rollback() {
    let participant = TransactionParticipant {
        adapter_key: "command-state".into(),
        tool_id: "command-state".into(),
    };
    let mut runtime = DispatchRuntime {
        receipt: receipt(vec![participant]),
        state_present: Cell::new(true),
        operations: RefCell::new(Vec::new()),
    };
    let adapter = CommandStateAdapter;

    let report =
        restore_execution(&context(), "tx-command-state", &[&adapter], &mut runtime).unwrap();

    assert!(report.receipt.verified);
    assert_eq!(report.adapter_key, "command-state");
    assert_eq!(
        runtime.operations.into_inner(),
        ["inspect-receipt", "read-state", "restore-files"]
    );
}

#[test]
fn unknown_or_multi_adapter_receipt_fails_without_restoring_files() {
    let unknown = TransactionParticipant {
        adapter_key: "missing".into(),
        tool_id: "missing".into(),
    };
    let mut runtime = DispatchRuntime {
        receipt: receipt(vec![unknown.clone()]),
        state_present: Cell::new(true),
        operations: RefCell::new(Vec::new()),
    };
    let adapter = CommandStateAdapter;
    assert!(matches!(
        restore_execution(&context(), "tx-command-state", &[&adapter], &mut runtime),
        Err(FrontendError::AdapterMissing(_))
    ));
    assert!(runtime.state_present.get());

    runtime.receipt.participants = vec![
        unknown,
        TransactionParticipant {
            adapter_key: "command-state".into(),
            tool_id: "command-state".into(),
        },
    ];
    assert!(
        restore_execution(&context(), "tx-command-state", &[&adapter], &mut runtime)
            .unwrap_err()
            .to_string()
            .contains("exactly one adapter")
    );
    assert!(runtime.state_present.get());
}
