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
