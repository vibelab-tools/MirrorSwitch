# WinGet adapter

The `winget` adapter supports Windows 10 1809 and later on x64, plus native Windows 11 ARM64.
It reads the WinGet/App Installer version and uses `winget source export` to capture source name,
type, argument, data/identifier, trust level, explicit flag, and optional priority. The `winget`
community source is the only mutable source; `msstore` and custom sources remain in their original
order and are never removed or recreated.

USTC and NJU publish valid `Microsoft.PreIndexed.Package` source roots. The catalog checks both
`source.msix` and `source2.msix`, then reads the merged jqlang.jq 1.8.2 manifest for the target x64
or arm64 installer URL and SHA-256. The MSIX packages contain Microsoft's source identity,
signature, and `Public/index.db`; an arbitrary directory URL cannot become a candidate.

## Version and state handling

WinGet 1.6 and 1.7 use the legacy source-add form. WinGet 1.8 and later add the mirror with
`--trust-level trusted`, as required by the published mirror instructions. Current versions also
restore the exported explicit/priority fields with `source edit`. A version that cannot preserve a
nondefault field is rejected rather than flattening source policy.

Source registration is command-managed, so the plan first writes a private recovery description to
`%LOCALAPPDATA%\MirrorSwitch\winget-source-state.json`. It contains only the original public
community source fields, the selected reviewed endpoint, and the WinGet version—never credentials
or custom sources. The transaction is applied before `source remove/add`; any command failure keeps
or consumes that file according to whether the original source was successfully restored.

MirrorSwitch never passes `--accept-source-agreements` or `--accept-package-agreements`. Existing
agreement state can therefore continue to work, while a source requiring new consent fails without
silently recording acceptance.

## Verification and recovery

After apply, WinGet must export the selected argument, update the source, find `jqlang.jq`, and
download its exact architecture into a temporary directory with WinGet's normal installer hash
check enabled. The temporary download is removed afterward. The mirror accelerates indexed source
metadata; the jq executable still comes from its manifest's GitHub Release URL and is not claimed
as mirror-hosted.

Verification failure restores the original community source and then rolls back the recovery file.
Explicit `mirrorswitch restore` inspects the transaction and dispatches this adapter before file
rollback, so command state is restored as well. A malformed recovery file, unexpected participant,
or incomplete source restoration remains recoverable and is not reported as verified.
