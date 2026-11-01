# Commit identity and privacy

This repository uses `Zero-Trace <78784941+zero-trace-usa@users.noreply.github.com>` for project-authored commits. The address is the established GitHub privacy address used by the repository's earlier commits. Configure both fields locally; global settings supplied by a development platform can change between sessions.

```sh
git config --local user.name Zero-Trace
git config --local user.email 78784941+zero-trace-usa@users.noreply.github.com
git var GIT_AUTHOR_IDENT
git var GIT_COMMITTER_IDENT
```

The owner requested removal of a former personal identity from recent history and tag metadata. This changes affected commit identifiers and the affected release tag's underlying identifiers. After a privacy rewrite, collaborators should make a fresh clone or carefully rebase clean work onto the sanitized history. Do not merge or push the old history back into the repository.

A display-name mapping does not remove original commit metadata, so the old alias mapping has been removed. Project files, commit/tag metadata, configured identity, saved environment instructions and release archives should be checked separately when verifying removal.

GitHub can retain unreachable commits, cached pages, pull-request refs and historical workflow records after a force push. Repository owners may need GitHub Support to purge retained views or objects. Existing forks, downloaded archives, other people's clones, search caches and prior chat records are outside a repository rewrite's control. Do not describe a Git rewrite as guaranteed erasure of every existing copy.

The repository-controlled cleanup removed the affected history metadata, literal identity aliases, 14 superseded workflow runs and 12 code-scanning analyses. The temporary cleanup workflow was removed after success. Reachable remote objects and all five published package/image assets were audited. A retained old commit page still exposed the prior identity after the rewrite; GitHub Support is required for that remaining cache/object cleanup.

A managed development platform may reapply a global Git identity between commands. The repository-local configuration and saved author/committer environment overrides take precedence for this project. The platform account's original identity setting must be corrected at its source to remove that provider-maintained copy; changing a ChatGPT display name alone does not do so.
