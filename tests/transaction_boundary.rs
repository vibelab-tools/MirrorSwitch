use std::{
    cell::Cell,
    fs, io,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    ApplyOutcome, TransactionEngine,
    catalog::ConfigurationScope,
    plan::{ChangePlan, PlannedFileChange, ServiceImpact},
    transaction::{FileOwner, FileSnapshot, FileSystem, OsFileSystem, TransactionError},
};
use tempfile::TempDir;

fn plan(changes: Vec<PlannedFileChange>) -> ChangePlan {
    plan_for("test", changes)
}

fn plan_for(tool_id: &str, changes: Vec<PlannedFileChange>) -> ChangePlan {
    ChangePlan {
        adapter_key: tool_id.into(),
        tool_id: tool_id.into(),
        scope: ConfigurationScope::User,
        changes,
        requires_elevation: false,
        service_impact: ServiceImpact::None,
    }
}

fn replacement(path: &Path, old: &[u8], new: &[u8]) -> PlannedFileChange {
    PlannedFileChange {
        target: path.to_path_buf(),
        old_contents: Some(old.to_vec()),
        old_mode: current_mode(path),
        new_contents: new.to_vec(),
        new_mode: Some(0o640),
        summary: "replace selected mirror".into(),
    }
}

#[cfg(unix)]
fn current_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(fs::metadata(path).unwrap().permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
fn current_mode(_path: &Path) -> Option<u32> {
    None
}

#[test]
fn preview_is_read_only_and_redacts_old_and_new_values() {
    let directory = TempDir::new().unwrap();
    let target = directory.path().join("pip.conf");
    fs::write(&target, b"password=old-secret\n").unwrap();
    let transaction = plan(vec![replacement(
        &target,
        b"password=old-secret\n",
        b"password=new-secret\n",
    )]);

    let preview = transaction.preview();

    assert_eq!(fs::read(&target).unwrap(), b"password=old-secret\n");
    assert_eq!(preview.changes[0].target, target);
    assert_eq!(preview.changes[0].old.bytes, 20);
    assert_eq!(preview.changes[0].new.bytes, 20);
    assert_ne!(preview.changes[0].old.sha256, preview.changes[0].new.sha256);
    let output = format!("{transaction:?} {preview:?}");
    assert!(!output.contains("old-secret"));
    assert!(!output.contains("new-secret"));
}

#[test]
fn apply_is_idempotent_and_selected_snapshot_restores_with_permissions() {
    let directory = TempDir::new().unwrap();
    let state = directory.path().join("state");
    let first = directory.path().join("first.conf");
    let second = directory.path().join("second.conf");
    fs::write(&first, b"token=first-old\nkeep=true\n").unwrap();
    fs::write(&second, b"token=second-old\n").unwrap();
    let transaction = plan(vec![
        replacement(
            &first,
            b"token=first-old\nkeep=true\n",
            b"token=first-new\nkeep=true\n",
        ),
        replacement(&second, b"token=second-old\n", b"token=second-new\n"),
    ]);
    let engine = TransactionEngine::new(&state);

    let ApplyOutcome::Applied(receipt) = engine.apply(&transaction).unwrap() else {
        panic!("the initial apply must write files");
    };
    assert_eq!(receipt.changed_files, 2);
    assert_eq!(fs::read(&first).unwrap(), b"token=first-new\nkeep=true\n");
    assert_eq!(engine.apply(&transaction).unwrap(), ApplyOutcome::Unchanged);
    assert_eq!(fs::read_dir(&state).unwrap().count(), 1);

    let manifest =
        fs::read_to_string(state.join(&receipt.transaction_id).join("manifest.json")).unwrap();
    assert!(!manifest.contains("first-old"));
    assert!(!manifest.contains("second-old"));
    assert_eq!(
        current_mode(&state.join(&receipt.transaction_id)),
        Some(0o700)
    );
    assert_eq!(
        current_mode(
            &state
                .join(&receipt.transaction_id)
                .join("backups/000000.bin")
        ),
        Some(0o600)
    );

    fs::write(&first, b"unrelated later value").unwrap();
    let restored = engine.restore(&receipt.transaction_id).unwrap();
    assert!(restored.verified);
    assert_eq!(restored.restored_files, 2);
    assert_eq!(fs::read(&first).unwrap(), b"token=first-old\nkeep=true\n");
    assert_eq!(fs::read(&second).unwrap(), b"token=second-old\n");
    assert_eq!(current_mode(&first), transaction.changes[0].old_mode);
}

#[test]
fn a_cross_tool_partial_write_failure_restores_already_applied_files() {
    let directory = TempDir::new().unwrap();
    let state = directory.path().join("state");
    let first = directory.path().join("first.conf");
    let second = directory.path().join("second.conf");
    fs::write(&first, b"first-old").unwrap();
    fs::write(&second, b"second-old").unwrap();
    let transactions = [
        plan_for(
            "first-tool",
            vec![replacement(&first, b"first-old", b"first-new")],
        ),
        plan_for(
            "second-tool",
            vec![replacement(&second, b"second-old", b"second-new")],
        ),
    ];
    let filesystem = FailOnTarget {
        inner: OsFileSystem,
        target: second.clone(),
        failed: Cell::new(false),
    };
    let engine = TransactionEngine::with_filesystem(state, filesystem);

    let error = engine.apply_all(&transactions).unwrap_err();
    let error_output = format!("{error:?} {error}");
    assert!(!error_output.contains("first-old"));
    assert!(!error_output.contains("first-new"));

    let TransactionError::ApplyFailed { rollback, .. } = error else {
        panic!("expected an apply failure");
    };
    assert_eq!(rollback.attempted, 1);
    assert_eq!(rollback.restored, 1);
    assert!(rollback.errors.is_empty());
    assert_eq!(fs::read(&first).unwrap(), b"first-old");
    assert_eq!(fs::read(&second).unwrap(), b"second-old");
}

#[test]
fn concurrent_change_causes_conflict_without_writes_or_backups() {
    let directory = TempDir::new().unwrap();
    let state = directory.path().join("state");
    let target = directory.path().join("config");
    fs::write(&target, b"observed").unwrap();
    let transaction = plan(vec![replacement(&target, b"observed", b"desired")]);
    fs::write(&target, b"changed-after-plan").unwrap();
    let engine = TransactionEngine::new(&state);

    assert!(matches!(
        engine.apply(&transaction),
        Err(TransactionError::Conflict { .. })
    ));
    assert_eq!(fs::read(&target).unwrap(), b"changed-after-plan");
    assert!(!state.exists());
}

#[test]
fn manifest_commit_failure_rolls_back_all_targets() {
    let directory = TempDir::new().unwrap();
    let state = directory.path().join("state");
    let target = directory.path().join("config");
    fs::write(&target, b"old-value").unwrap();
    let transaction = plan(vec![replacement(&target, b"old-value", b"new-value")]);
    let engine = TransactionEngine::with_filesystem(
        state,
        FailManifestCommit {
            inner: OsFileSystem,
            manifest_writes: Cell::new(0),
        },
    );

    let error = engine.apply(&transaction).unwrap_err();

    let TransactionError::CommitFailed { rollback, .. } = error else {
        panic!("expected the manifest commit to fail");
    };
    assert_eq!(rollback.attempted, 1);
    assert_eq!(rollback.restored, 1);
    assert!(rollback.errors.is_empty());
    assert_eq!(fs::read(&target).unwrap(), b"old-value");
}

struct FailOnTarget {
    inner: OsFileSystem,
    target: PathBuf,
    failed: Cell<bool>,
}

impl FileSystem for FailOnTarget {
    fn snapshot(&self, path: &Path) -> io::Result<FileSnapshot> {
        self.inner.snapshot(path)
    }

    fn create_private_dir(&self, path: &Path) -> io::Result<()> {
        self.inner.create_private_dir(path)
    }

    fn write_private(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
        self.inner.write_private(path, contents)
    }

    fn atomic_replace(
        &self,
        path: &Path,
        contents: &[u8],
        mode: Option<u32>,
        owner: Option<FileOwner>,
    ) -> io::Result<()> {
        if path == self.target && !self.failed.replace(true) {
            return Err(io::Error::other("injected write failure"));
        }
        self.inner.atomic_replace(path, contents, mode, owner)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        self.inner.remove_file(path)
    }
}

struct FailManifestCommit {
    inner: OsFileSystem,
    manifest_writes: Cell<usize>,
}

impl FileSystem for FailManifestCommit {
    fn snapshot(&self, path: &Path) -> io::Result<FileSnapshot> {
        self.inner.snapshot(path)
    }

    fn create_private_dir(&self, path: &Path) -> io::Result<()> {
        self.inner.create_private_dir(path)
    }

    fn write_private(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
        self.inner.write_private(path, contents)
    }

    fn atomic_replace(
        &self,
        path: &Path,
        contents: &[u8],
        mode: Option<u32>,
        owner: Option<FileOwner>,
    ) -> io::Result<()> {
        if path.file_name().is_some_and(|name| name == "manifest.json") {
            let write = self.manifest_writes.get();
            self.manifest_writes.set(write + 1);
            if write == 1 {
                return Err(io::Error::other("injected manifest commit failure"));
            }
        }
        self.inner.atomic_replace(path, contents, mode, owner)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        self.inner.remove_file(path)
    }
}
