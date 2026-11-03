# CLAUDE.md

## 1. Project
- **Purpose:** PowerShell inventory of F5 BIG-IP LTM virtual servers, pools, pool members and SSL certificates through iControl REST, with CSV/JSON output and an HTML dashboard.
- **Status:** TBD (draft / active / maintenance). **Tier:** tool.
- **Public repository.** Everything committed here is world-readable. This is the highest-risk repo for leaking real data.
- **Safety stance:** read-only against devices.
- **Data rule:** sanitized material only. No employer data, secrets, customer data, or unsanitized device configs or logs. Use documentation ranges 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32, example.com and `<redacted>`. Private terms to block (an employer domain, internal hostnames) belong in the git-ignored `.sanitize-deny.local`, never in a committed file.

## 2. Stack
- PowerShell 5.1 and 7 (`#Requires -Version 5.1`). No module dependencies.
- Run: `.\Get-F5LtmInventory.ps1 -BigIpHost ...` (parameter-driven) or `.\Get-F5LtmInventory_v2.ps1` (interactive).
- Lint: PSScriptAnalyzer with `PSScriptAnalyzerSettings.psd1`. Only Error findings fail the check.
- Tests: TBD. No Pester suite yet.
- Checks: `bash scripts/check.sh` (`--fast` in the pre-commit hook, `--strict` in CI). Enable the hook per clone with `git config core.hooksPath .githooks`.

## 3. Git rules
- Visibility: this repo is **public** (existing). Never make another repo public without an explicit instruction for that repo.
- Commit only when asked. A commit request is not approval to push, merge, or open a PR. Pushing to a public repo is an external action: confirm first.
- `main` plus short-lived feature branches; PRs once the repo is shared.
- Commit messages: imperative summary, reason in the body when not obvious. Small logical commits.
- Warn before force pushes, history rewrites, or discarding work.

## 4. Versioning
- Semantic Versioning. Annotated tags `vMAJOR.MINOR.PATCH`. Current version: **1.0.1**.
- **Release contract:** script parameters and prompts, host CSV format, output file names and columns, the certificate association values.
- **Major:** different prompts, renamed or removed parameters, changed output file names or columns, changed documented values. **Minor:** opt-in feature that leaves existing runs unchanged. **Patch:** fix or change that does not affect behavior.
- **Version lives in:** the `Version:` line of both scripts, the README "Current version" line, the newest `CHANGELOG.md` heading, and the tag. `scripts/check.sh` verifies they agree.
- **History file:** `CHANGELOG.md` (Keep a Changelog). Docs-only and repo-tooling changes go under `[Unreleased]` and need no bump or tag.
- `Get-F5LtmInventory_v2.ps1` has "v2" in its file name but is the interactive variant at version 1.0.1, not a second major version. Renaming it would break existing users; decide deliberately before changing it.

## 5. Conventions
- Follow the existing style. No new dependencies without discussion.
- Credentials: `PSCredential` or an `Export-Clixml` file; never plaintext arguments; credential files are never committed. Certificate verification stays on by default.
- Example inputs: `f5-hosts.example.csv` is tracked with placeholders; the real `f5-hosts.csv` is git-ignored.
- Generated reports are git-ignored; `Sample-F5-Dashboard.html` is the only tracked report and must contain placeholder data only.

## 6. Out of scope
- Never add the ability to change a BIG-IP device.
- Never commit real inventory output, hostnames, addresses, usernames or tokens.

## 7. Baseline checklist
- [x] README
- [x] .gitignore, .gitattributes
- [x] Example input file
- [x] CHANGELOG.md (Keep a Changelog)
- [x] CLAUDE.md
- [x] Check entrypoint, pre-commit hook, analyzer settings, CI workflow
- [ ] LICENSE decision: TBD (this is a public repo with no license; the README states that none is granted)
- [ ] Tests: TBD
- [ ] Status: TBD
- [ ] With approval: branch protection on `main`, secret scanning and push protection, Dependabot

## 8. Code standards
- For code implementation, debugging, refactoring, testing, and review tasks, invoke the `code-standards` skill before making changes.
