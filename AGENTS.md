# Git identity and privacy

For every commit in this repository, configure both the author and committer identity:

```sh
git config --local user.name Zero-Trace
git config --local user.email 78784941+zero-trace-usa@users.noreply.github.com
```

Check `git var GIT_AUTHOR_IDENT` and `git var GIT_COMMITTER_IDENT` before committing. Both must use the name and GitHub privacy email above. Never inherit a personal email address from global or platform Git configuration. A ChatGPT display-name change does not configure Git.

Do not add historical personal-identity aliases to `.mailmap`, documentation or generated files. Preserve the sanitized identity when applying patches or making releases. Changing published history requires explicit user authorization; the repository privacy cleanup was explicitly requested by its owner.
