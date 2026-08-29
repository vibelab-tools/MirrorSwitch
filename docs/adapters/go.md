# Go Modules adapter

The Go Modules adapter supports the stable Go `1.13+` module environment model on Linux
`x86_64` and `arm64`. Detection records the Go version, the effective `GOPROXY` chain and its
comma/pipe separator model, the persistent `GOENV` path, checksum-database state, private-module
policy state, and any process-level `GOPROXY` override. The behavior follows the official
[Go Modules reference](https://go.dev/ref/mod#environment-variables) and
[module proxy protocol](https://go.dev/ref/mod#goproxy-protocol).

The only writable scope is the user `GOENV` file reported by `go env`. MirrorSwitch replaces
exactly one recognized public proxy entry and preserves all private or enterprise proxy entries,
`direct`/`off` tokens, and every original separator. A comma keeps Go's 404/410-only fallback;
a pipe keeps fallback on any error. Chains with no recognized public entry or multiple public
entries are rejected rather than reordered or expanded. A process-level `GOPROXY` override and
`GOENV=off` also block the plan because a persistent edit would not be effective.

`GOPRIVATE`, `GONOPROXY`, `GONOSUMDB`, `GOSUMDB`, `GO111MODULE`, enterprise URLs, credentials,
and unrelated Go settings are never rewritten. Private-module patterns therefore continue to
bypass public proxies and the public checksum database. MirrorSwitch rejects `GOSUMDB=off`, a
global checksum bypass, a global proxy bypass, and `GO111MODULE=off`; it never weakens these
policies to make a candidate pass.

The Alibaba Cloud, Huawei Cloud, and Nanjing University records are derived from their official
[Alibaba Cloud instructions](https://developer.aliyun.com/mirror/goproxy),
[Huawei Cloud listing](https://mirrors.huaweicloud.com/v1/repositories), and
[NJU addition inventory](https://mirrors.nju.edu.cn/configs/addition.json). Before latency ranking,
an actionable candidate must serve the reviewed module's version list, `.info`, `.mod`, `.zip`,
and the `sum.golang.org` `supported` and checksum lookup protocol. Alibaba Cloud currently passes
that complete flow. Huawei Cloud and NJU serve all four module objects but return 404 for the
embedded checksum-database protocol, so v0.1 keeps them visible but excludes them before latency
ranking instead of silently combining them with a separate checksum service. After apply,
MirrorSwitch confirms the effective value through `go env` and runs
`go mod download -json github.com/pkg/errors@v0.9.1`; both module and `go.mod` `h1:` checksums must
be present. Failure restores the exact prior `GOENV` file, replanning is idempotent, and CLI,
configuration-file, and TUI entry points consume the same plan.
