# Git Commit Rules

This document defines the recommended branch, commit, staging, verification,
push, and pull request rules for this repository.

## Core Principles

- Only create commits when explicitly asked by a user or maintainer.
- Do not commit automatically after making changes.
- Each commit must express one logical, testable change.
- Do not mix unrelated features, fixes, refactors, tests, or documentation
  changes in the same commit.
- When a set of changes contains multiple types or functional scopes, split it
  into multiple commits.
- Do not bypass checks with `--no-verify`.
- Do not rewrite shared history that other contributors may have based work on.

## Branch Names

Use clear topic branches such as:

- `codex/<topic>`
- `feature/<topic>`
- `fix/<topic>`
- `docs/<topic>`

Write `<topic>` in short, descriptive English kebab-case, for example
`codex/git-rules` or `fix/login-timeout`.

## Author Identity

Before committing, make sure the local Git author identity is configured:

```bash
git config --local user.name
git config --local user.email
```

If the local repository does not have `user.name` or `user.email` configured,
use the repository-local fallback identity:

```bash
git config --local user.name "ziliang"
git config --local user.email "ziliangzhangcok@gmail.com"
```

Prefer repository-local configuration for this fallback. Do not change global
Git identity unless explicitly asked.

## Commit Message Format

Use Conventional Commits:

```text
<type>(<scope>): <subject>
```

Omit `scope` for repo-wide changes:

```text
<type>: <subject>
```

### type

Recommended types:

- `feat`: a new feature or capability
- `fix`: a bug fix
- `refactor`: an internal change that does not alter external behavior
- `test`: new or updated tests
- `docs`: documentation changes
- `chore`: build, configuration, dependency, or maintenance changes
- `perf`: a performance improvement

Use only one `type` per commit. If a batch of work contains a feature, a docs
update, and a refactor, split it into separate commits.

### scope

`scope` identifies the affected area, for example:

- an algorithm or feature name: `grpo`, `opd`
- a shared library: `rl_common`
- a submodule: `rl_common/trainer`
- a product or workflow module: `generation`, `runner`, `verification`

Omit `scope` when the change affects the whole repository.

### subject

Write `subject` in:

- English
- imperative mood
- lowercase
- no trailing period
- 72 characters or fewer when practical

Examples:

```text
feat(grpo): add group-relative advantage loss
fix(runner): preserve tool errors in trajectory
refactor(rl_common): extract shared base trainer
test(verification): cover hard-check reward gating
docs(architecture): explain environment boundary
docs: add git commit rules
```

## Commit Body

For behavioral changes, data format changes, or compatibility-sensitive changes,
explain the following in the commit body:

- motivation
- implementation approach
- data, schema, or export format impact
- compatibility impact
- verification method and test results
- rollback plan

## Staging Rules

- Stage files by explicit path, for example `git add README.md`.
- Do not use `git add -A` or `git add .`.
- Before committing, inspect `git status --short` and `git diff --cached`.
- Do not stage local experiment scripts, temporary outputs, model files,
  datasets, secrets, or cache files.

Never commit:

- `.env`, API keys, tokens, or credential files
- `runs/`, `outputs/`, or `checkpoints/`
- `models/`, `datasets/`, model weights, or unlicensed data
- `__pycache__/`, `.pytest_cache/`, or build caches
- large generated artifacts or one-off smoke-test outputs

## Verification Rules

Before committing, run verification that matches the scope of the change:

- Documentation changes: check formatting, links, and example commands.
- Code changes: ensure imports resolve and relevant unit tests or offline smoke
  tests pass.
- Behavioral changes: add or update tests and record the key verification
  results.
- Data or schema changes: explain migration, compatibility, and rollback
  behavior.

If a check cannot be run, state the reason in the commit body, pull request
description, or delivery note.

## Push Rules

- After completing user-requested or maintainer-requested local commits, push
  them to the configured remote.
- Do not push if the user explicitly asks to keep commits local or if no remote
  is available.
- Before pushing, confirm that the current branch and remote target are correct.

## Pull Request Rules

Pull request descriptions should cover:

- problem background
- solution
- data, schema, or compatibility impact
- test results
- cost, safety, or privacy impact
- rollback plan

Keep pull requests focused. Do not combine unrelated topics in a single pull
request.

## Recommended Workflow

```bash
git status --short
git diff
git config --local user.name || git config --local user.name "ziliang"
git config --local user.email || git config --local user.email "ziliangzhangcok@gmail.com"
git add <explicit-path>
git diff --cached
git commit -m "docs: add git commit rules"
git push origin <branch>
```
