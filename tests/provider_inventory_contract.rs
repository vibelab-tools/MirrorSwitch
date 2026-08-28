use std::collections::{HashMap, HashSet};

use serde_json::Value;

const INVENTORY: &str = include_str!("../catalog/provider-inventory.json");

#[test]
fn inventory_covers_six_official_sources_with_strict_record_fields() {
    let document: Value = serde_json::from_str(INVENTORY).unwrap();
    assert_eq!(document["schema_version"], 1);
    let observed_at = document["observed_at"].as_str().unwrap();
    assert!(observed_at.ends_with('Z'));

    let providers = document["providers"].as_array().unwrap();
    let provider_ids: HashSet<_> = providers
        .iter()
        .map(|provider| provider["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        provider_ids,
        HashSet::from(["aliyun", "huaweicloud", "ustc", "tuna", "nju", "sjtug"])
    );

    let allowed_content_types = HashSet::from([
        "repository-metadata",
        "binary-cache",
        "container-registry",
        "git-mirror",
        "release-proxy",
        "raw-proxy",
        "language-registry",
        "release-artifacts",
        "static-files",
    ]);
    let entries = document["entries"].as_array().unwrap();
    assert!(entries.len() >= 1_000);
    let mut ids = HashSet::new();
    let mut identities = HashSet::new();
    let mut counts: HashMap<&str, u64> = HashMap::new();
    for entry in entries {
        let id = entry["id"].as_str().unwrap();
        assert!(ids.insert(id));
        let provider = entry["provider_id"].as_str().unwrap();
        assert!(provider_ids.contains(provider));
        *counts.entry(provider).or_default() += 1;
        let raw_name = entry["raw_name"].as_str().unwrap();
        assert!(!raw_name.is_empty());
        let source_url = entry["source_url"].as_str().unwrap();
        assert!(source_url.starts_with("https://"));
        assert!(identities.insert((provider, raw_name, source_url)));
        assert_eq!(entry["observed_at"], observed_at);

        let normalized = entry["normalized_upstream"].as_str().unwrap();
        assert!(!normalized.is_empty());
        assert_eq!(normalized, normalized.to_lowercase());
        assert!(allowed_content_types.contains(entry["content_type"].as_str().unwrap()));
        assert_eq!(entry["inventory_state"], "cataloged");

        let endpoints = entry["public_endpoints"].as_array().unwrap();
        assert!(!endpoints.is_empty());
        for endpoint in endpoints {
            let url = endpoint["url"].as_str().unwrap();
            assert!(url.starts_with("https://") || url.starts_with("http://"));
            assert_eq!(endpoint["protocol"], url.split(':').next().unwrap());
            assert!(!endpoint["derivation"].as_str().unwrap().is_empty());
        }

        let compatibility = &entry["compatibility"];
        for os in compatibility["operating_systems"].as_array().unwrap() {
            assert!(["linux", "macos", "windows"].contains(&os.as_str().unwrap()));
        }
        for architecture in compatibility["architectures"].as_array().unwrap() {
            assert!(["x86_64", "arm64"].contains(&architecture.as_str().unwrap()));
        }
        assert!(compatibility["distributions"].is_array());
        assert!(compatibility["versions"].is_array());
        assert!(!compatibility["evidence"].as_str().unwrap().is_empty());

        match entry["adapter_state"].as_str().unwrap() {
            "planned" => {
                let targets = entry["adapter_targets"].as_array().unwrap();
                assert!(!targets.is_empty());
                for target in targets {
                    assert_eq!(target["state"], "planned");
                    let issue = target["issue"].as_str().unwrap();
                    let issue_number: u32 = issue.rsplit('/').next().unwrap().parse().unwrap();
                    assert!((27..=107).contains(&issue_number));
                }
            }
            "not-supported" => assert!(entry["adapter_targets"].as_array().unwrap().is_empty()),
            state => panic!("unexpected adapter state {state}"),
        }
        assert!(
            ["passed", "pending-adapter"]
                .contains(&entry["validation"]["status"].as_str().unwrap())
        );
    }

    for provider in providers {
        let id = provider["id"].as_str().unwrap();
        assert_eq!(
            provider["included_entries"].as_u64(),
            counts.get(id).copied()
        );
        let sources = provider["source_snapshots"].as_array().unwrap();
        assert!(!sources.is_empty());
        for source in sources {
            assert!(source["url"].as_str().unwrap().starts_with("https://"));
            assert_eq!(source["sha256"].as_str().unwrap().len(), 64);
            assert!(
                source["discovered_entries"].as_u64().unwrap()
                    >= source["included_entries"].as_u64().unwrap()
            );
        }
    }
}

#[test]
fn content_checks_probe_repository_metadata_instead_of_provider_roots() {
    let document: Value = serde_json::from_str(INVENTORY).unwrap();
    let probes = document["content_probes"].as_array().unwrap();
    assert_eq!(probes.len(), 6);
    let mut providers = HashSet::new();
    for probe in probes {
        assert_eq!(probe["result"], "passed");
        assert_eq!(
            probe["expected_content"],
            "APT InRelease clear-signed metadata"
        );
        let provider = probe["provider_id"].as_str().unwrap();
        assert!(providers.insert(provider));
        let endpoint = probe["endpoint"].as_str().unwrap();
        let probe_url = probe["probe_url"].as_str().unwrap();
        assert!(probe_url.starts_with(endpoint));
        assert_ne!(probe_url, endpoint);
        assert!(probe_url.ends_with("/InRelease"));
        assert_eq!(probe["response_sha256_prefix"].as_str().unwrap().len(), 64);
    }
}

#[test]
fn remote_inventory_contains_no_executable_extension_fields() {
    let document: Value = serde_json::from_str(INVENTORY).unwrap();
    reject_executable_fields(&document);
}

#[test]
fn aliases_normalize_without_merging_distinct_content_surfaces() {
    let document: Value = serde_json::from_str(INVENTORY).unwrap();
    let entries = document["entries"].as_array().unwrap();
    for raw_name in ["brew.git", "homebrew.git"] {
        let matches: Vec<_> = entries
            .iter()
            .filter(|entry| entry["raw_name"] == raw_name)
            .collect();
        assert!(!matches.is_empty());
        assert!(matches.iter().all(|entry| {
            entry["normalized_upstream"] == "homebrew" && entry["content_type"] == "git-mirror"
        }));
    }

    let ubuntu_types: HashSet<_> = entries
        .iter()
        .filter(|entry| entry["provider_id"] == "aliyun")
        .filter(|entry| {
            ["ubuntu", "ubuntu-ports", "ubuntu-releases"]
                .contains(&entry["normalized_upstream"].as_str().unwrap())
        })
        .map(|entry| {
            (
                entry["normalized_upstream"].as_str().unwrap(),
                entry["content_type"].as_str().unwrap(),
            )
        })
        .collect();
    assert!(ubuntu_types.contains(&("ubuntu", "repository-metadata")));
    assert!(ubuntu_types.contains(&("ubuntu-ports", "repository-metadata")));
    assert!(ubuntu_types.contains(&("ubuntu-releases", "release-artifacts")));
}

fn reject_executable_fields(value: &Value) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                assert!(!["command", "script", "program", "executable"].contains(&key.as_str()));
                reject_executable_fields(value);
            }
        }
        Value::Array(values) => values.iter().for_each(reject_executable_fields),
        _ => {}
    }
}
