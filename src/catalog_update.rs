use std::{
    collections::HashSet,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(unix)]
use std::fs::File;

use reqwest::blocking::Client;
use serde::Serialize;
use tempfile::NamedTempFile;
use thiserror::Error;

use crate::catalog::{CatalogValidationError, MirrorCatalog};

pub const DEFAULT_CATALOG_URL: &str =
    "https://raw.githubusercontent.com/vibelab-tools/MirrorSwitch/main/catalog/mirrors.json";
pub const EMBEDDED_CATALOG: &[u8] = include_bytes!("../catalog/mirrors.json");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FetchLimits {
    pub timeout: Duration,
    pub max_bytes: usize,
}

impl Default for FetchLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            max_bytes: 8 * 1024 * 1024,
        }
    }
}

pub trait CatalogTransport {
    fn fetch(&self, url: &str, limits: FetchLimits) -> Result<Vec<u8>, CatalogFetchError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct HttpCatalogTransport;

impl CatalogTransport for HttpCatalogTransport {
    fn fetch(&self, url: &str, limits: FetchLimits) -> Result<Vec<u8>, CatalogFetchError> {
        let client = Client::builder()
            .timeout(limits.timeout)
            .build()
            .map_err(|error| CatalogFetchError::Http(error.to_string()))?;
        let mut response = client
            .get(url)
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .map_err(map_reqwest_error)?;

        if response
            .content_length()
            .is_some_and(|length| length > limits.max_bytes as u64)
        {
            return Err(CatalogFetchError::TooLarge {
                limit_bytes: limits.max_bytes,
            });
        }

        let mut body = Vec::new();
        response
            .by_ref()
            .take(limits.max_bytes as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|error| CatalogFetchError::Http(error.to_string()))?;
        if body.len() > limits.max_bytes {
            return Err(CatalogFetchError::TooLarge {
                limit_bytes: limits.max_bytes,
            });
        }
        Ok(body)
    }
}

fn map_reqwest_error(error: reqwest::Error) -> CatalogFetchError {
    if error.is_timeout() {
        CatalogFetchError::Timeout
    } else {
        CatalogFetchError::Http(error.to_string())
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CatalogFetchError {
    #[error("catalog request timed out")]
    Timeout,
    #[error("catalog exceeds the {limit_bytes}-byte limit")]
    TooLarge { limit_bytes: usize },
    #[error("catalog request failed: {0}")]
    Http(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CatalogSource {
    EmbeddedBaseline,
    LastKnownGoodCache,
    FreshRemote,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum CacheStatus {
    Missing,
    Valid { content_revision: u64 },
    Stale { content_revision: u64 },
    Invalid { reason: String },
    Unreadable { reason: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum CatalogUpdateResult {
    Updated {
        previous_revision: u64,
        content_revision: u64,
    },
    NoUpdate,
    StaleRemote {
        content_revision: u64,
    },
    RevisionConflict {
        content_revision: u64,
    },
    FetchFailed {
        kind: FetchFailureKind,
        message: String,
    },
    InvalidRemote {
        reason: String,
    },
    CacheWriteFailed {
        reason: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FetchFailureKind {
    Timeout,
    TooLarge,
    Http,
}

impl From<&CatalogFetchError> for FetchFailureKind {
    fn from(error: &CatalogFetchError) -> Self {
        match error {
            CatalogFetchError::Timeout => Self::Timeout,
            CatalogFetchError::TooLarge { .. } => Self::TooLarge,
            CatalogFetchError::Http(_) => Self::Http,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CatalogStatus {
    pub schema_version: u32,
    pub content_version: String,
    pub content_revision: u64,
    pub generated_at: String,
    pub source: CatalogSource,
    pub cache: CacheStatus,
    pub update: CatalogUpdateResult,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedCatalog {
    pub catalog: MirrorCatalog,
    pub status: CatalogStatus,
}

pub struct CatalogUpdater<T> {
    baseline: Vec<u8>,
    raw_url: String,
    cache_path: PathBuf,
    limits: FetchLimits,
    transport: T,
}

impl CatalogUpdater<HttpCatalogTransport> {
    pub fn new(cache_path: impl Into<PathBuf>) -> Self {
        Self::from_parts(
            EMBEDDED_CATALOG.to_vec(),
            DEFAULT_CATALOG_URL,
            cache_path,
            FetchLimits::default(),
            HttpCatalogTransport,
        )
    }
}

impl<T: CatalogTransport> CatalogUpdater<T> {
    pub fn from_parts(
        baseline: Vec<u8>,
        raw_url: impl Into<String>,
        cache_path: impl Into<PathBuf>,
        limits: FetchLimits,
        transport: T,
    ) -> Self {
        Self {
            baseline,
            raw_url: raw_url.into(),
            cache_path: cache_path.into(),
            limits,
            transport,
        }
    }

    pub fn load(
        &self,
        adapter_allowlist: &HashSet<String>,
    ) -> Result<LoadedCatalog, CatalogLoadError> {
        let baseline = parse_and_validate(&self.baseline, adapter_allowlist)
            .map_err(CatalogLoadError::InvalidEmbeddedCatalog)?;
        let mut current = baseline;
        let mut source = CatalogSource::EmbeddedBaseline;

        let mut cache = match fs::read(&self.cache_path) {
            Ok(bytes) => match parse_and_validate(&bytes, adapter_allowlist) {
                Ok(catalog) if catalog.content_revision > current.content_revision => {
                    let revision = catalog.content_revision;
                    current = catalog;
                    source = CatalogSource::LastKnownGoodCache;
                    CacheStatus::Valid {
                        content_revision: revision,
                    }
                }
                Ok(catalog) => CacheStatus::Stale {
                    content_revision: catalog.content_revision,
                },
                Err(error) => CacheStatus::Invalid {
                    reason: error.to_string(),
                },
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => CacheStatus::Missing,
            Err(error) => CacheStatus::Unreadable {
                reason: error.to_string(),
            },
        };

        let update = match self.transport.fetch(&self.raw_url, self.limits) {
            Err(error) => CatalogUpdateResult::FetchFailed {
                kind: (&error).into(),
                message: error.to_string(),
            },
            Ok(bytes) => match parse_and_validate(&bytes, adapter_allowlist) {
                Err(error) => CatalogUpdateResult::InvalidRemote {
                    reason: error.to_string(),
                },
                Ok(remote) if remote.content_revision < current.content_revision => {
                    CatalogUpdateResult::StaleRemote {
                        content_revision: remote.content_revision,
                    }
                }
                Ok(remote) if remote.content_revision == current.content_revision => {
                    if remote == current {
                        CatalogUpdateResult::NoUpdate
                    } else {
                        CatalogUpdateResult::RevisionConflict {
                            content_revision: remote.content_revision,
                        }
                    }
                }
                Ok(remote) => {
                    let previous_revision = current.content_revision;
                    match write_cache_atomically(&self.cache_path, &bytes) {
                        Ok(()) => {
                            current = remote;
                            source = CatalogSource::FreshRemote;
                            cache = CacheStatus::Valid {
                                content_revision: current.content_revision,
                            };
                            CatalogUpdateResult::Updated {
                                previous_revision,
                                content_revision: current.content_revision,
                            }
                        }
                        Err(error) => CatalogUpdateResult::CacheWriteFailed {
                            reason: error.to_string(),
                        },
                    }
                }
            },
        };

        let status = CatalogStatus {
            schema_version: current.schema_version,
            content_version: current.content_version.clone(),
            content_revision: current.content_revision,
            generated_at: current.generated_at.clone(),
            source,
            cache,
            update,
        };
        Ok(LoadedCatalog {
            catalog: current,
            status,
        })
    }
}

fn parse_and_validate(
    bytes: &[u8],
    adapter_allowlist: &HashSet<String>,
) -> Result<MirrorCatalog, CatalogDataError> {
    let catalog: MirrorCatalog = serde_json::from_slice(bytes)?;
    catalog.validate(adapter_allowlist)?;
    Ok(catalog)
}

fn write_cache_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    sync_directory(parent)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[derive(Debug, Error)]
pub enum CatalogDataError {
    #[error("catalog JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("catalog semantics are invalid: {0}")]
    Validation(#[from] CatalogValidationError),
}

#[derive(Debug, Error)]
pub enum CatalogLoadError {
    #[error("embedded catalog is invalid: {0}")]
    InvalidEmbeddedCatalog(CatalogDataError),
}
