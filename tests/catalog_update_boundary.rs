use std::{
    cell::RefCell,
    collections::HashSet,
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    thread,
    time::Duration,
};

use mirrorswitch::catalog_update::{
    CacheStatus, CatalogFetchError, CatalogSource, CatalogTransport, CatalogUpdateResult,
    CatalogUpdater, FetchFailureKind, FetchLimits, HttpCatalogTransport,
};
use serde_json::{Value, json};
use tempfile::tempdir;

fn catalog(revision: u64) -> Value {
    json!({
        "schema_version": 1,
        "content_version": format!("2026.08.28.{revision}"),
        "content_revision": revision,
        "generated_at": "2026-08-28T00:00:00Z",
        "providers": [{
            "id": "example",
            "display_name": "Example",
            "catalog_source": "https://example.invalid"
        }],
        "upstreams": [{
            "id": "pypi--language-registry",
            "family": "pypi",
            "display_name": "PyPI",
            "content_kind": "language-registry",
            "aliases": ["pypi"]
        }],
        "tools": [{
            "id": "pip",
            "adapter_key": "pip",
            "display_name": "pip",
            "state": "planned",
            "implementation_issue": "https://github.com/vibelab-tools/MirrorSwitch/issues/39",
            "supported_scopes": ["user"],
            "composition": "single"
        }],
        "candidates": [{
            "id": "example-pypi-pip",
            "provider_id": "example",
            "upstream_id": "pypi--language-registry",
            "tool_id": "pip",
            "catalog_state": "cataloged",
            "raw_names": ["pypi"],
            "endpoints": [{
                "role": "index",
                "protocol": "https",
                "url": "https://example.invalid/pypi/simple"
            }],
            "compatibility": {
                "operating_systems": ["linux"],
                "architectures": ["x86-64"],
                "environments": ["host"],
                "distributions": [],
                "repository_versions": []
            },
            "probes": [],
            "source_urls": ["https://example.invalid/help/pypi"],
            "observed_at": "2026-08-28T00:00:00Z"
        }]
    })
}

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

struct FixedTransport {
    response: RefCell<Option<Result<Vec<u8>, CatalogFetchError>>>,
}

impl FixedTransport {
    fn returning(response: Result<Vec<u8>, CatalogFetchError>) -> Self {
        Self {
            response: RefCell::new(Some(response)),
        }
    }
}

impl CatalogTransport for FixedTransport {
    fn fetch(&self, _url: &str, _limits: FetchLimits) -> Result<Vec<u8>, CatalogFetchError> {
        self.response.borrow_mut().take().unwrap()
    }
}

fn updater(
    baseline: &Value,
    cache: &Path,
    response: Result<Vec<u8>, CatalogFetchError>,
) -> CatalogUpdater<FixedTransport> {
    CatalogUpdater::from_parts(
        bytes(baseline),
        "https://example.invalid/catalog.json",
        cache,
        FetchLimits {
            timeout: Duration::from_millis(50),
            max_bytes: 4096,
        },
        FixedTransport::returning(response),
    )
}

#[test]
fn first_offline_run_uses_embedded_baseline() {
    let directory = tempdir().unwrap();
    let loaded = updater(
        &catalog(1),
        &directory.path().join("catalog.json"),
        Err(CatalogFetchError::Http("offline".into())),
    )
    .load(&HashSet::new())
    .unwrap();

    assert_eq!(loaded.catalog.content_revision, 1);
    assert_eq!(loaded.status.source, CatalogSource::EmbeddedBaseline);
    assert_eq!(loaded.status.cache, CacheStatus::Missing);
    assert!(matches!(
        loaded.status.update,
        CatalogUpdateResult::FetchFailed {
            kind: FetchFailureKind::Http,
            ..
        }
    ));
}

#[test]
fn newer_remote_is_atomically_cached_and_becomes_last_known_good() {
    let directory = tempdir().unwrap();
    let cache = directory.path().join("catalog.json");
    let remote = bytes(&catalog(2));
    let loaded = updater(&catalog(1), &cache, Ok(remote.clone()))
        .load(&HashSet::new())
        .unwrap();

    assert_eq!(loaded.status.source, CatalogSource::FreshRemote);
    assert_eq!(fs::read(&cache).unwrap(), remote);
    assert_eq!(
        loaded.status.update,
        CatalogUpdateResult::Updated {
            previous_revision: 1,
            content_revision: 2,
        }
    );
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);

    let offline = updater(
        &catalog(1),
        &cache,
        Err(CatalogFetchError::Http("offline".into())),
    )
    .load(&HashSet::new())
    .unwrap();
    assert_eq!(offline.catalog.content_revision, 2);
    assert_eq!(offline.status.source, CatalogSource::LastKnownGoodCache);
}

#[test]
fn unchanged_and_older_remote_catalogs_do_not_replace_current_data() {
    let directory = tempdir().unwrap();
    let cache = directory.path().join("catalog.json");
    let unchanged = updater(&catalog(2), &cache, Ok(bytes(&catalog(2))))
        .load(&HashSet::new())
        .unwrap();
    assert_eq!(unchanged.status.update, CatalogUpdateResult::NoUpdate);
    assert!(!cache.exists());

    fs::write(&cache, bytes(&catalog(3))).unwrap();
    let stale = updater(&catalog(1), &cache, Ok(bytes(&catalog(2))))
        .load(&HashSet::new())
        .unwrap();
    assert_eq!(stale.catalog.content_revision, 3);
    assert_eq!(
        stale.status.update,
        CatalogUpdateResult::StaleRemote {
            content_revision: 2
        }
    );
}

#[test]
fn timeout_and_oversized_responses_keep_the_baseline() {
    let directory = tempdir().unwrap();
    for (error, expected_kind) in [
        (CatalogFetchError::Timeout, FetchFailureKind::Timeout),
        (
            CatalogFetchError::TooLarge { limit_bytes: 10 },
            FetchFailureKind::TooLarge,
        ),
    ] {
        let loaded = updater(
            &catalog(1),
            &directory.path().join("catalog.json"),
            Err(error),
        )
        .load(&HashSet::new())
        .unwrap();
        assert!(matches!(
            loaded.status.update,
            CatalogUpdateResult::FetchFailed { kind, .. } if kind == expected_kind
        ));
        assert_eq!(loaded.catalog.content_revision, 1);
    }
}

#[test]
fn truncated_invalid_schema_and_unknown_adapter_responses_are_rejected() {
    let directory = tempdir().unwrap();
    let mut unsupported_schema = catalog(2);
    unsupported_schema["schema_version"] = json!(2);
    let mut unknown_adapter = catalog(2);
    unknown_adapter["tools"][0]["state"] = json!("supported");
    unknown_adapter["tools"][0]["adapter_key"] = json!("remote-plugin");

    for response in [
        b"{\"schema_version\":".to_vec(),
        bytes(&unsupported_schema),
        bytes(&unknown_adapter),
    ] {
        let loaded = updater(
            &catalog(1),
            &directory.path().join("catalog.json"),
            Ok(response),
        )
        .load(&HashSet::new())
        .unwrap();
        assert!(matches!(
            loaded.status.update,
            CatalogUpdateResult::InvalidRemote { .. }
        ));
        assert_eq!(loaded.catalog.content_revision, 1);
    }
}

#[test]
fn corrupt_cache_is_reported_and_preserved_when_remote_is_invalid() {
    let directory = tempdir().unwrap();
    let cache = directory.path().join("catalog.json");
    fs::write(&cache, b"not-json").unwrap();

    let loaded = updater(&catalog(1), &cache, Ok(b"also-not-json".to_vec()))
        .load(&HashSet::new())
        .unwrap();
    assert!(matches!(loaded.status.cache, CacheStatus::Invalid { .. }));
    assert!(matches!(
        loaded.status.update,
        CatalogUpdateResult::InvalidRemote { .. }
    ));
    assert_eq!(fs::read(&cache).unwrap(), b"not-json");
    assert_eq!(loaded.catalog.content_revision, 1);
}

#[test]
fn real_http_transport_enforces_content_length_limit() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0; 1024];
        let _ = stream.read(&mut request).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
            .unwrap();
    });

    let error = HttpCatalogTransport
        .fetch(
            &format!("http://{address}/catalog.json"),
            FetchLimits {
                timeout: Duration::from_secs(1),
                max_bytes: 10,
            },
        )
        .unwrap_err();
    server.join().unwrap();
    assert_eq!(error, CatalogFetchError::TooLarge { limit_bytes: 10 });
}

#[test]
fn first_online_run_fetches_valid_catalog_through_http_boundary() {
    let remote = bytes(&catalog(2));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0; 1024];
        let _ = stream.read(&mut request).unwrap();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            remote.len()
        )
        .unwrap();
        stream.write_all(&remote).unwrap();
    });

    let directory = tempdir().unwrap();
    let cache = directory.path().join("catalog.json");
    let loaded = CatalogUpdater::from_parts(
        bytes(&catalog(1)),
        format!("http://{address}/catalog.json"),
        &cache,
        FetchLimits {
            timeout: Duration::from_secs(1),
            max_bytes: 4096,
        },
        HttpCatalogTransport,
    )
    .load(&HashSet::new())
    .unwrap();
    server.join().unwrap();

    assert_eq!(loaded.catalog.content_revision, 2);
    assert_eq!(loaded.status.source, CatalogSource::FreshRemote);
    assert!(cache.exists());
}
