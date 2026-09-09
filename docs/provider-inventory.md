# Reviewed provider inventory snapshot

The checked-in [provider inventory](../catalog/provider-inventory.json) is a
point-in-time discovery snapshot, not a support claim. It records every entry
found through the initial six official public listings and reviewed tool-specific providers, then normalizes aliases,
content type, explicitly evidenced platform dimensions, candidate endpoints,
adapter planning state, and source provenance.

## Initial broad snapshot on 2026-08-28

| Provider | Official discovery source | Discovered | Included | Notes |
| --- | --- | ---: | ---: | --- |
| Alibaba Cloud | [two-page public mirror directory](https://developer.aliyun.com/mirror/) | 190 page occurrences | 187 unique routes | Three routes occur on both pages. Candidate paths use the provider's documented `mirrors.aliyun.com/<name>/` convention and still require adapter probes. |
| Huawei Cloud | [repository API](https://mirrors.huaweicloud.com/v1/repositories) | 141 | 141 | Published `mirrorPath`/download URLs are retained. For 28 entries without a published path, a clearly marked name-path candidate is retained for later content validation. |
| USTC | [help index](https://mirrors.ustc.edu.cn/help/index.html) | 95 links | 90 repositories | The canonical self-link and contributor/index/quickstart/rsync-guide documentation pages are excluded with reasons. |
| Tsinghua TUNA | [official mirror-web enabled list](https://github.com/tuna/mirror-web/blob/master/_helpz/enabled.yaml) | 123 | 123 | The source SHA-256 is stored so enabled-list changes are reviewable. |
| Nanjing University | [tunasync status](https://mirrors.nju.edu.cn/configs/tunasync.json) + [additional paths](https://mirrors.nju.edu.cn/configs/addition.json) | 371 + 165 | 536 source records | Same names from distinct official sources remain distinct records; explicit addition paths and inheritance are preserved. |
| SJTUG | [manager status API](https://mirror.sjtu.edu.cn/lug/v1/manager/summary) | 123 worker keys | 122 repositories | Internal `.mirrorz` status worker is excluded with a reason. |

## Tool-specific additions on 2026-09-09

| Provider | Published source | Included | Notes |
| --- | --- | ---: | --- |
| DaoCloud | [public-image-mirror instructions](https://github.com/DaoCloud/public-image-mirror) | 1 | Publishes `https://docker.m.daocloud.io` for Docker daemon `registry-mirrors`; Registry v2 Bearer auth, architecture manifest, config and layer remain runtime probes. |
| 1Panel | [container settings documentation](https://1panel.cn/docs/v2/user_manual/containers/setting/) | 1 | Publishes `https://docker.1panel.live` as a Docker mirror; the same runtime content probes apply. |
| Qilu University of Technology | [tunasync status](https://mirrors.qlu.edu.cn/static/tunasync.json) | 1 | Publishes a current ROS 2 mirror; signed Ubuntu metadata and exact amd64/arm64 packages remain runtime probes. |
| Zhejiang University | [MirrorZ status](https://mirrors.zju.edu.cn/api/mirrorz.json) | 1 | Publishes a current ROS 2 mirror with the same runtime package checks. |
| Xi'an Jiaotong University | [mirror status](https://mirrors.xjtu.edu.cn/.well-known/mirrorz-org-mirrors.json) | 1 | Publishes a current ROS 2 mirror with the same runtime package checks. |
| Nanyang Institute of Technology | [tunasync status](https://mirror.nyist.edu.cn/static/tunasync.json) | 1 | Publishes a current ROS 2 mirror with the same runtime package checks. |
| lework Jenkins Update Center | [immutable signed metadata](https://github.com/lework/jenkins-update-center/tree/3df56b0ada4fc57ca1329946697eb0f896389047) | 5 | Five JSONP variants pair one pinned third-party certificate with Alibaba Cloud, Huawei Cloud, Tencent Cloud, TUNA, or USTC plugin artifacts. Each metadata and HPI body has an exact runtime digest. |

The snapshot contains 1,212 records. Current classification totals are 214
repository-metadata, 69 language-registry, 11 binary-cache, 7
container-registry, 157 Git mirror, 4 release proxy, 2 raw proxy, 66 release
artifacts, and 682 static/otherwise unclassified file trees. The large final
class is intentional: a directory name is not enough evidence to invent a
configuration protocol.

There are 447 provider records mapped to already-created adapter Issues and 765
kept as `not-supported`. `planned` still does not mean the current binary can
configure the entry. Each mapping links to the relevant per-tool Issue; shared
upstreams such as PyPI, npm, Maven, and NuGet retain multiple tool-specific
targets rather than pretending one configuration fits every client.

## Platform and content boundaries

Platform fields contain only what the public listing or repository identity
supports. Empty arrays mean “unspecified by the provider,” not “all OSes” or
“all architectures.” In particular:

- Homebrew Git/API/Bottles, MacPorts, and CocoaPods are classified as macOS
  surfaces and map to the v0.2 adapter Issues.
- WinGet, Scoop, Chocolatey, MSYS2, Cygwin, and PowerShell Gallery are Windows
  surfaces; NuGet is explicitly cross-platform and has separate Windows work.
- Ubuntu and Ubuntu Ports, Arch Linux and Arch Linux ARM, release archives,
  package metadata, container registries, and Git mirrors remain distinct
  upstream/content identities.
- Huawei `x86`/`arm` catalog tags and names such as `ubuntu-ports` are retained
  as evidence; no architecture is inferred from a generic directory.

## Content evidence

The refresh run retains the six baseline package-metadata probes. Those checks fetch a bounded
prefix of an Ubuntu or Debian `InRelease` file and require the OpenPGP clear-signed header. The
tool-specific Docker providers instead receive Registry v2 manifest and blob probes in the runtime
catalog. Provider homepages and repository roots are not accepted as content evidence.

Every other record remains `pending-adapter`. Its tool-specific Issue must
define the exact metadata, representative package/artifact, architecture, and
client semantics before the record can move from `cataloged` to `supported`.

## Refresh and review

Run from the repository root:

```bash
python3 scripts/refresh_provider_inventory.py --probe
git diff -- catalog/provider-inventory.json
cargo test --test provider_inventory_contract
```

The refresh uses only Python's standard library. Each reviewed response stores
its URL, retrieval time, SHA-256, discovered/included counts, and explicit
exclusions. Stable record IDs make additions, removals, renames, and source
moves visible in review. The contract test rejects missing provenance or
compatibility fields, unknown content classes, invalid adapter Issue links,
homepage-only probes, duplicate identities, and executable extension fields.
