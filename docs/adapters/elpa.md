# package.el/ELPA adapter

Issues [#80](https://github.com/vibelab-tools/MirrorSwitch/issues/80) and
[#138](https://github.com/vibelab-tools/MirrorSwitch/issues/138) implement the
package.el boundary for reviewed GNU Emacs 27 through 31. Linux supports
x86_64 and arm64 hosts and containers. macOS supports native Intel and Apple
Silicon Emacs. Windows supports the reviewed native x64 GNU Emacs build;
Windows arm64 is rejected because no equivalent reviewed native build exists.

MirrorSwitch asks Emacs in quick batch mode for its expanded home,
`user-emacs-directory`, `system-type`, and `system-configuration`. This follows
the native Windows AppData/HOME rules and the XDG or `.emacs.d` choice made by
Emacs itself. Existing `.emacs.el`, `.emacs`, Windows `_emacs`, and
`user-emacs-directory/init.el` files are considered; multiple candidates stop
the plan instead of guessing. The project directory is only reported as
read-only context.

The adapter appends one managed package.el block or replaces its prior managed
block. All user Lisp outside that block remains byte-for-byte unchanged,
including custom/private archives, credentials, certificate and proxy policy,
`package-archive-priorities`, `custom-file`, unknown forms, UTF-8 BOM, native
line endings, permissions, and ACLs. Status and plan output report counts and
paths rather than user Lisp or URL contents.

## Independent archive selection

GNU ELPA, NonGNU ELPA, and MELPA are separate upstreams. NJU, TUNA, and USTC
currently expose all three reviewed subtrees, producing nine independent
candidates. Each candidate must pass its own `archive-contents`, fixed package,
and metadata checks before latency comparison. GNU and NonGNU additionally
require the published archive and package signatures; MELPA remains explicitly
upstream-unsigned. The bounded selection response budget accommodates the
complete MELPA index, so it is inspected rather than rejected only because it
exceeds the original small-response ceiling.

After apply, Emacs runs `package-refresh-contents` in an isolated package
directory with only the three selected endpoints and requires all three native
archive indexes. `allow-unsigned` permits MELPA while still rejecting invalid
signatures where signatures are present. A failed batch refresh restores the
original init bytes; repeated application is a no-op.

The manual native workflow installs Emacs 30.2 on macOS Intel, macOS Apple
Silicon, and Windows x64. It verifies Emacs-reported native architecture and
paths, CLI/configuration/TUI plan equality, isolated archive refresh,
idempotence, and exact restoration of the init file, project fixture,
permissions, and ACLs.
