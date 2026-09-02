use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::plan::{ChangePlan, PlannedFileChange};

static TRANSACTION_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileSnapshot {
    pub contents: Option<Vec<u8>>,
    pub mode: Option<u32>,
    pub owner: Option<FileOwner>,
    pub windows_attributes: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileOwner {
    pub uid: u32,
    pub gid: u32,
}

/// Filesystem boundary used by the transaction engine. Tests can inject an I/O
/// failure while the production implementation continues to use real files.
pub trait FileSystem {
    fn snapshot(&self, path: &Path) -> io::Result<FileSnapshot>;
    fn create_private_dir(&self, path: &Path) -> io::Result<()>;
    fn write_private(&self, path: &Path, contents: &[u8]) -> io::Result<()>;
    fn atomic_replace(
        &self,
        path: &Path,
        contents: &[u8],
        mode: Option<u32>,
        owner: Option<FileOwner>,
        windows_attributes: Option<u32>,
    ) -> io::Result<()>;
    fn remove_file(&self, path: &Path) -> io::Result<()>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct OsFileSystem;

impl FileSystem for OsFileSystem {
    fn snapshot(&self, path: &Path) -> io::Result<FileSnapshot> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if !metadata.is_file() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "transaction target is not a regular file",
                    ));
                }
                Ok(FileSnapshot {
                    contents: Some(fs::read(path)?),
                    mode: permission_mode(&metadata),
                    owner: file_owner(&metadata),
                    windows_attributes: platform_attributes(path)?,
                })
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(FileSnapshot {
                contents: None,
                mode: None,
                owner: None,
                windows_attributes: None,
            }),
            Err(error) => Err(error),
        }
    }

    fn create_private_dir(&self, path: &Path) -> io::Result<()> {
        fs::create_dir_all(path)?;
        set_mode(path, 0o700)
    }

    fn write_private(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            self.create_private_dir(parent)?;
        }
        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true);
        set_creation_mode(&mut options, 0o600);
        let mut file = options.open(path)?;
        file.write_all(contents)?;
        file.sync_all()?;
        set_mode(path, 0o600)
    }

    fn atomic_replace(
        &self,
        path: &Path,
        contents: &[u8],
        mode: Option<u32>,
        owner: Option<FileOwner>,
        windows_attributes: Option<u32>,
    ) -> io::Result<()> {
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "target has no parent directory",
            )
        })?;
        fs::create_dir_all(parent)?;

        let sequence = TRANSACTION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("config");
        let temporary = parent.join(format!(
            ".{file_name}.mirrorswitch-{}-{sequence}.tmp",
            std::process::id()
        ));

        let result = (|| {
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            set_creation_mode(&mut options, mode.unwrap_or(0o600));
            let mut file = options.open(&temporary)?;
            file.write_all(contents)?;
            set_file_owner(&file, owner)?;
            set_file_mode(&file, mode.unwrap_or(0o600))?;
            file.sync_all()?;
            drop(file);
            replace_path(&temporary, path, windows_attributes)?;
            set_platform_attributes(path, windows_attributes)
        })();

        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        match remove_path(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TransactionEngine<F = OsFileSystem> {
    state_root: PathBuf,
    filesystem: F,
}

impl TransactionEngine<OsFileSystem> {
    pub fn new(state_root: impl Into<PathBuf>) -> Self {
        Self::with_filesystem(state_root, OsFileSystem)
    }
}

impl<F: FileSystem> TransactionEngine<F> {
    pub fn with_filesystem(state_root: impl Into<PathBuf>, filesystem: F) -> Self {
        Self {
            state_root: state_root.into(),
            filesystem,
        }
    }

    pub fn apply(&self, plan: &ChangePlan) -> Result<ApplyOutcome, TransactionError> {
        self.apply_all(std::slice::from_ref(plan))
    }

    /// Applies plans from multiple adapters as one rollback boundary.
    pub fn apply_all(&self, plans: &[ChangePlan]) -> Result<ApplyOutcome, TransactionError> {
        validate_plans(plans)?;

        let mut pending = Vec::new();
        for plan in plans {
            for change in &plan.changes {
                let current = self.snapshot(&change.target, "read transaction target")?;
                if matches_desired(&current, change) {
                    continue;
                }
                if !matches_planned_state(&current, change) {
                    return Err(TransactionError::Conflict {
                        path: change.target.clone(),
                    });
                }
                pending.push((change, current));
            }
        }

        if pending.is_empty() {
            return Ok(ApplyOutcome::Unchanged);
        }

        let transaction_id = transaction_id();
        let transaction_dir = self.state_root.join(&transaction_id);
        let backup_dir = transaction_dir.join("backups");
        self.create_private_dir(&transaction_dir, "create transaction directory")?;
        self.create_private_dir(&backup_dir, "create transaction directory")?;

        let mut records = Vec::with_capacity(pending.len());
        for (index, (change, snapshot)) in pending.iter().enumerate() {
            let backup = if let Some(contents) = &snapshot.contents {
                let relative = PathBuf::from(format!("backups/{index:06}.bin"));
                self.write_private(
                    &transaction_dir.join(&relative),
                    contents,
                    "write transaction backup",
                )?;
                Some(relative)
            } else {
                None
            };
            records.push(BackupRecord {
                target: change.target.clone(),
                backup,
                original_digest: snapshot.contents.as_deref().map(content_digest),
                original_mode: snapshot.mode,
                original_owner: snapshot.owner,
                original_windows_attributes: snapshot.windows_attributes,
                applied_digest: content_digest(&change.new_contents),
                applied_mode: requested_mode(change, snapshot),
                applied_owner: snapshot.owner,
                applied_windows_attributes: snapshot.windows_attributes,
            });
        }

        let mut manifest = TransactionManifest {
            schema_version: 1,
            transaction_id: transaction_id.clone(),
            participants: plans
                .iter()
                .map(|plan| TransactionParticipant {
                    adapter_key: plan.adapter_key.clone(),
                    tool_id: plan.tool_id.clone(),
                })
                .collect(),
            status: TransactionStatus::Applying,
            records,
        };
        self.write_manifest(&transaction_dir, &manifest)?;

        for (applied, ((change, _), record)) in pending.iter().zip(&manifest.records).enumerate() {
            if let Err(error) = self.filesystem.atomic_replace(
                &change.target,
                &change.new_contents,
                record.applied_mode,
                record.applied_owner,
                record.applied_windows_attributes,
            ) {
                let rollback =
                    self.rollback_records(&transaction_dir, &manifest.records[..applied]);
                manifest.status = if rollback.errors.is_empty() {
                    TransactionStatus::RolledBack
                } else {
                    TransactionStatus::RollbackFailed
                };
                let _ = self.write_manifest(&transaction_dir, &manifest);
                return Err(TransactionError::ApplyFailed {
                    path: change.target.clone(),
                    source: error,
                    rollback,
                });
            }
        }

        manifest.status = TransactionStatus::Applied;
        if let Err(source) = self.write_manifest(&transaction_dir, &manifest) {
            let rollback = self.rollback_records(&transaction_dir, &manifest.records);
            manifest.status = if rollback.errors.is_empty() {
                TransactionStatus::RolledBack
            } else {
                TransactionStatus::RollbackFailed
            };
            let _ = self.write_manifest(&transaction_dir, &manifest);
            return Err(TransactionError::CommitFailed {
                source: Box::new(source),
                rollback,
            });
        }

        Ok(ApplyOutcome::Applied(TransactionReceipt {
            transaction_id,
            participants: manifest.participants,
            changed_files: pending.len(),
            changed_targets: pending
                .iter()
                .map(|(change, _)| change.target.clone())
                .collect(),
        }))
    }

    pub fn restore(&self, transaction_id: &str) -> Result<RestoreReceipt, TransactionError> {
        validate_transaction_id(transaction_id)?;
        let transaction_dir = self.state_root.join(transaction_id);
        let mut manifest = self.read_manifest(&transaction_dir)?;
        if manifest.transaction_id != transaction_id {
            return Err(TransactionError::InvalidManifest(
                "transaction identifier does not match directory".into(),
            ));
        }

        let rollback = self.rollback_records(&transaction_dir, &manifest.records);
        if !rollback.errors.is_empty() {
            return Err(TransactionError::RestoreFailed { rollback });
        }

        for record in &manifest.records {
            let actual = self.snapshot(&record.target, "verify restored target")?;
            if !matches_original(&actual, record) {
                return Err(TransactionError::VerificationFailed {
                    path: record.target.clone(),
                });
            }
        }

        manifest.status = TransactionStatus::Restored;
        self.write_manifest(&transaction_dir, &manifest)?;
        Ok(RestoreReceipt {
            transaction_id: transaction_id.into(),
            restored_files: manifest.records.len(),
            verified: true,
        })
    }

    fn rollback_records(&self, transaction_dir: &Path, records: &[BackupRecord]) -> RollbackReport {
        let mut report = RollbackReport::default();
        for record in records.iter().rev() {
            report.attempted += 1;
            let result = match &record.backup {
                Some(relative) => self.restore_backup(transaction_dir, record, relative),
                None => self.filesystem.remove_file(&record.target),
            };
            match result {
                Ok(()) => report.restored += 1,
                Err(error) => report.errors.push(RollbackFailure {
                    path: record.target.clone(),
                    message: error.to_string(),
                }),
            }
        }
        report
    }

    fn restore_backup(
        &self,
        transaction_dir: &Path,
        record: &BackupRecord,
        relative: &Path,
    ) -> io::Result<()> {
        validate_relative_backup(relative)?;
        let backup = self.filesystem.snapshot(&transaction_dir.join(relative))?;
        let contents = backup.contents.ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "transaction backup is missing")
        })?;
        if record.original_digest.as_deref() != Some(content_digest(&contents).as_str()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "backup digest does not match manifest",
            ));
        }
        self.filesystem.atomic_replace(
            &record.target,
            &contents,
            record.original_mode,
            record.original_owner,
            record.original_windows_attributes,
        )
    }

    fn read_manifest(
        &self,
        transaction_dir: &Path,
    ) -> Result<TransactionManifest, TransactionError> {
        let path = transaction_dir.join("manifest.json");
        let snapshot = self.snapshot(&path, "read transaction manifest")?;
        let contents = snapshot
            .contents
            .ok_or_else(|| TransactionError::NotFound {
                transaction_id: transaction_dir
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or("<invalid>")
                    .into(),
            })?;
        serde_json::from_slice(&contents).map_err(TransactionError::ManifestJson)
    }

    fn write_manifest(
        &self,
        transaction_dir: &Path,
        manifest: &TransactionManifest,
    ) -> Result<(), TransactionError> {
        let contents =
            serde_json::to_vec_pretty(manifest).map_err(TransactionError::ManifestJson)?;
        let path = transaction_dir.join("manifest.json");
        self.filesystem
            .atomic_replace(&path, &contents, Some(0o600), None, None)
            .map_err(|source| TransactionError::Io {
                operation: "write transaction manifest",
                path,
                source,
            })
    }

    fn snapshot(
        &self,
        path: &Path,
        operation: &'static str,
    ) -> Result<FileSnapshot, TransactionError> {
        self.filesystem
            .snapshot(path)
            .map_err(|source| TransactionError::Io {
                operation,
                path: path.to_path_buf(),
                source,
            })
    }

    fn create_private_dir(
        &self,
        path: &Path,
        operation: &'static str,
    ) -> Result<(), TransactionError> {
        self.filesystem
            .create_private_dir(path)
            .map_err(|source| TransactionError::Io {
                operation,
                path: path.to_path_buf(),
                source,
            })
    }

    fn write_private(
        &self,
        path: &Path,
        contents: &[u8],
        operation: &'static str,
    ) -> Result<(), TransactionError> {
        self.filesystem
            .write_private(path, contents)
            .map_err(|source| TransactionError::Io {
                operation,
                path: path.to_path_buf(),
                source,
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum ApplyOutcome {
    Applied(TransactionReceipt),
    Unchanged,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TransactionReceipt {
    pub transaction_id: String,
    pub participants: Vec<TransactionParticipant>,
    pub changed_files: usize,
    pub changed_targets: Vec<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionParticipant {
    pub adapter_key: String,
    pub tool_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RestoreReceipt {
    pub transaction_id: String,
    pub restored_files: usize,
    pub verified: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RollbackReport {
    pub attempted: usize,
    pub restored: usize,
    pub errors: Vec<RollbackFailure>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollbackFailure {
    pub path: PathBuf,
    pub message: String,
}

#[derive(Debug, Error)]
pub enum TransactionError {
    #[error("transaction plan contains duplicate target {path}")]
    DuplicateTarget { path: PathBuf },
    #[error("transaction target changed after planning: {path}")]
    Conflict { path: PathBuf },
    #[error("invalid transaction identifier")]
    InvalidTransactionId,
    #[error("transaction {transaction_id} was not found")]
    NotFound { transaction_id: String },
    #[error("invalid transaction manifest: {0}")]
    InvalidManifest(String),
    #[error("transaction manifest is invalid: {0}")]
    ManifestJson(serde_json::Error),
    #[error("failed to {operation} at {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to apply transaction target {path}; rollback: {rollback:?}")]
    ApplyFailed {
        path: PathBuf,
        #[source]
        source: io::Error,
        rollback: RollbackReport,
    },
    #[error("failed to commit transaction manifest; rollback: {rollback:?}")]
    CommitFailed {
        #[source]
        source: Box<TransactionError>,
        rollback: RollbackReport,
    },
    #[error("transaction restore was incomplete: {rollback:?}")]
    RestoreFailed { rollback: RollbackReport },
    #[error("restored target failed verification: {path}")]
    VerificationFailed { path: PathBuf },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransactionManifest {
    schema_version: u32,
    transaction_id: String,
    participants: Vec<TransactionParticipant>,
    status: TransactionStatus,
    records: Vec<BackupRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupRecord {
    target: PathBuf,
    backup: Option<PathBuf>,
    original_digest: Option<String>,
    original_mode: Option<u32>,
    original_owner: Option<FileOwner>,
    #[serde(default)]
    original_windows_attributes: Option<u32>,
    applied_digest: String,
    applied_mode: Option<u32>,
    applied_owner: Option<FileOwner>,
    #[serde(default)]
    applied_windows_attributes: Option<u32>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TransactionStatus {
    Applying,
    Applied,
    RolledBack,
    RollbackFailed,
    Restored,
}

pub fn content_digest(contents: &[u8]) -> String {
    format!("{:x}", Sha256::digest(contents))
}

#[cfg(not(windows))]
fn validate_plans(plans: &[ChangePlan]) -> Result<(), TransactionError> {
    let mut targets = HashSet::new();
    for plan in plans {
        for change in &plan.changes {
            if !targets.insert(&change.target) {
                return Err(TransactionError::DuplicateTarget {
                    path: change.target.clone(),
                });
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn validate_plans(plans: &[ChangePlan]) -> Result<(), TransactionError> {
    let mut targets = HashSet::new();
    for plan in plans {
        for change in &plan.changes {
            let key = change
                .target
                .to_string_lossy()
                .replace('/', "\\")
                .to_lowercase();
            if !targets.insert(key) {
                return Err(TransactionError::DuplicateTarget {
                    path: change.target.clone(),
                });
            }
        }
    }
    Ok(())
}

fn matches_desired(snapshot: &FileSnapshot, change: &PlannedFileChange) -> bool {
    snapshot.contents.as_deref() == Some(change.new_contents.as_slice())
        && mode_matches(change.new_mode, snapshot.mode)
}

fn matches_planned_state(snapshot: &FileSnapshot, change: &PlannedFileChange) -> bool {
    snapshot.contents == change.old_contents && mode_matches(change.old_mode, snapshot.mode)
}

fn requested_mode(change: &PlannedFileChange, snapshot: &FileSnapshot) -> Option<u32> {
    change.new_mode.or(snapshot.mode).or(Some(0o600))
}

fn matches_original(snapshot: &FileSnapshot, record: &BackupRecord) -> bool {
    let digest = snapshot.contents.as_deref().map(content_digest);
    digest == record.original_digest
        && mode_matches(record.original_mode, snapshot.mode)
        && record
            .original_owner
            .is_none_or(|owner| snapshot.owner == Some(owner))
        && record
            .original_windows_attributes
            .is_none_or(|attributes| snapshot.windows_attributes == Some(attributes))
}

fn mode_matches(expected: Option<u32>, actual: Option<u32>) -> bool {
    expected.is_none() || actual.is_none() || expected == actual
}

fn transaction_id() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let sequence = TRANSACTION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!(
        "{:016x}-{:08x}-{:08x}",
        duration.as_nanos(),
        std::process::id(),
        sequence
    )
}

fn validate_transaction_id(value: &str) -> Result<(), TransactionError> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(TransactionError::InvalidTransactionId);
    }
    Ok(())
}

fn validate_relative_backup(path: &Path) -> io::Result<()> {
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "backup path is not a safe relative path",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn permission_mode(metadata: &fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(metadata.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
fn permission_mode(_metadata: &fs::Metadata) -> Option<u32> {
    None
}

#[cfg(unix)]
fn file_owner(metadata: &fs::Metadata) -> Option<FileOwner> {
    use std::os::unix::fs::MetadataExt;
    Some(FileOwner {
        uid: metadata.uid(),
        gid: metadata.gid(),
    })
}

#[cfg(not(unix))]
fn file_owner(_metadata: &fs::Metadata) -> Option<FileOwner> {
    None
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_file_owner(file: &fs::File, owner: Option<FileOwner>) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let Some(owner) = owner else {
        return Ok(());
    };
    if file_owner(&file.metadata()?) == Some(owner) {
        return Ok(());
    }
    // SAFETY: `file` owns a valid descriptor for the duration of this call.
    let result = unsafe { libc::fchown(file.as_raw_fd(), owner.uid, owner.gid) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn set_file_owner(_file: &fs::File, _owner: Option<FileOwner>) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_file_mode(file: &fs::File, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_file_mode(_file: &fs::File, _mode: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_creation_mode(options: &mut OpenOptions, mode: u32) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(mode);
}

#[cfg(not(unix))]
fn set_creation_mode(_options: &mut OpenOptions, _mode: u32) {}

#[cfg(windows)]
fn wide_path(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

#[cfg(windows)]
fn platform_attributes(path: &Path) -> io::Result<Option<u32>> {
    use windows_sys::Win32::Storage::FileSystem::{GetFileAttributesW, INVALID_FILE_ATTRIBUTES};

    let path = wide_path(path);
    // SAFETY: `path` is a NUL-terminated UTF-16 buffer that remains alive for the call.
    let attributes = unsafe { GetFileAttributesW(path.as_ptr()) };
    if attributes == INVALID_FILE_ATTRIBUTES {
        Err(io::Error::last_os_error())
    } else {
        Ok(Some(attributes))
    }
}

#[cfg(not(windows))]
fn platform_attributes(_path: &Path) -> io::Result<Option<u32>> {
    Ok(None)
}

#[cfg(windows)]
fn set_platform_attributes(path: &Path, attributes: Option<u32>) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::SetFileAttributesW;

    let Some(attributes) = attributes else {
        return Ok(());
    };
    let path = wide_path(path);
    // SAFETY: `path` is a NUL-terminated UTF-16 buffer that remains alive for the call.
    if unsafe { SetFileAttributesW(path.as_ptr(), attributes) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn set_platform_attributes(_path: &Path, _attributes: Option<u32>) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn writable_attributes(attributes: u32) -> u32 {
    use windows_sys::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY};

    let writable = attributes & !FILE_ATTRIBUTE_READONLY;
    if writable == 0 {
        FILE_ATTRIBUTE_NORMAL
    } else {
        writable
    }
}

#[cfg(windows)]
fn replace_path(temporary: &Path, target: &Path, attributes: Option<u32>) -> io::Result<()> {
    use std::ptr;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_WRITE_THROUGH, MoveFileExW, REPLACEFILE_WRITE_THROUGH, ReplaceFileW,
    };

    let target_wide = wide_path(target);
    let temporary_wide = wide_path(temporary);
    let existed = target.exists();
    if existed {
        if let Some(attributes) = attributes {
            set_platform_attributes(target, Some(writable_attributes(attributes)))?;
        }
    }
    // SAFETY: both path buffers are NUL-terminated and valid for the duration of the call.
    let replaced = unsafe {
        if existed {
            ReplaceFileW(
                target_wide.as_ptr(),
                temporary_wide.as_ptr(),
                ptr::null(),
                REPLACEFILE_WRITE_THROUGH,
                ptr::null(),
                ptr::null(),
            )
        } else {
            MoveFileExW(
                temporary_wide.as_ptr(),
                target_wide.as_ptr(),
                MOVEFILE_WRITE_THROUGH,
            )
        }
    };
    if replaced == 0 {
        let error = io::Error::last_os_error();
        if existed {
            let _ = set_platform_attributes(target, attributes);
        }
        Err(error)
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn replace_path(temporary: &Path, target: &Path, _attributes: Option<u32>) -> io::Result<()> {
    fs::rename(temporary, target)
}

#[cfg(windows)]
fn remove_path(path: &Path) -> io::Result<()> {
    match platform_attributes(path) {
        Ok(Some(attributes)) => {
            set_platform_attributes(path, Some(writable_attributes(attributes)))?;
            match fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(error) => {
                    let _ = set_platform_attributes(path, Some(attributes));
                    Err(error)
                }
            }
        }
        Ok(None) => fs::remove_file(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(error),
        Err(error) => Err(error),
    }
}

#[cfg(not(windows))]
fn remove_path(path: &Path) -> io::Result<()> {
    fs::remove_file(path)
}
