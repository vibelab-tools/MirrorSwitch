# Safe change transactions

MirrorSwitch plans and applies changes as separate operations. Building or
displaying a plan only reads current files. Its public preview contains target
paths, content sizes and SHA-256 digests, old/new permission modes, elevation
requirements, and a human summary; configuration bytes are redacted from
`Debug` output.

Before the first target is replaced, apply creates a private transaction
directory and writes one backup per existing target. The JSON manifest records
only paths, digests, modes, participating adapter/tool identifiers, and
transaction status. `apply_all` groups plans from multiple tools into this same
rollback boundary.
Configuration contents live in separate mode-`0600` backup files and are never
copied into the manifest or error text. On Unix, original mode and ownership
are applied to replacement files and recorded for restore.

Every target is checked against the state observed during planning. If it
already matches the desired bytes and mode it is skipped; if it matches neither
the old nor desired state, apply stops with a conflict before creating backups.
This makes an identical plan idempotent without hiding concurrent edits.

Target writes use a temporary file in the target directory followed by rename.
If a later target fails, targets already changed by this transaction are
restored in reverse order and the error carries a structured rollback report.
Unknown content is not inferred or deleted by the transaction layer: adapters
must render complete files from the configuration they read.

A successful transaction ID selects a historical snapshot. Restore validates
the ID and backup paths, verifies each backup digest before writing, restores
the original existence and permission mode, then reads every target back and
compares it to the manifest before marking the transaction restored.

## macOS and Windows behavior

macOS uses the same Unix mode, owner, same-directory temporary file, rename, and directory sync
path as Linux. Its default transaction root is inside the user's Application Support directory;
system adapters may choose a separately authorized root later, but they do not get a second
transaction implementation.

Windows creates and flushes the temporary file in the target directory, closes its handle, then
uses the native replace/move API with write-through enabled. Keeping the temporary file on the
same parent also avoids cross-drive and UNC rename behavior. Existing read-only, hidden, system,
and related file attributes are recorded in the manifest, cleared only when Windows requires it
for replacement/removal, and restored on the resulting file. A target held with an exclusive
sharing lock fails before its contents are lost.

Windows target identities are case-insensitive for duplicate detection, so `Config.ini` and
`config.ini` cannot appear as two changes in one transaction. Transaction IDs and relative backup
paths retain the same traversal checks on every platform.

The Windows manifest does not serialize file contents, credentials, or security descriptors. The
transaction directory inherits the current user's LocalAppData ACL. v0.2 does not claim arbitrary
ACL, alternate data stream, or extended-attribute restoration; an adapter that requires those
properties must reject the target before planning until a native preservation boundary exists.

## Adapter-aware explicit restore

`mirrorswitch restore` first inspects an applied transaction manifest without changing its targets.
The receipt must name exactly one compiled adapter and the recorded tool identity must agree with
that adapter. The CLI then calls the adapter's restore boundary instead of bypassing it. Existing
file-backed adapters still delegate directly to the transaction engine, so the stable
`receipt.transaction_id`, `restored_files`, and `verified` JSON fields are unchanged.

This ordering also supports command-managed state. Such an adapter stores only the minimum private,
non-credential recovery description as a transactional file. During explicit restore it reads and
validates that description, restores the external command state, and only then asks the transaction
engine to restore or remove the recovery file. An unknown adapter, multiple participants, a corrupt
manifest, or a transaction that is no longer applied fails before adapter dispatch.
