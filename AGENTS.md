# Git commit identity

Use `Zero-Trace` as the Git author and committer name for this repository. A ChatGPT display-name change does not update Git configuration.

Before creating a commit, run `git config --local user.name Zero-Trace` and check `git var GIT_AUTHOR_IDENT` and `git var GIT_COMMITTER_IDENT`. Preserve the user's configured email unless they explicitly request an email change. Do not use an inherited `Zero-Trace` author name or invent an email address.

The repository's `.mailmap` maps the previous display name for supported history views. Preserve published release tags and existing commit history when correcting future attribution.
