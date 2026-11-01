# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- README, `.gitignore`, `.gitattributes`, `CLAUDE.md`, repository checks (`scripts/check.sh`, pre-commit
  hook, CI workflow) and PSScriptAnalyzer settings. No script behavior changed.

### Changed

- `f5-hosts.csv` is now the template `f5-hosts.example.csv`; the real `f5-hosts.csv` is git-ignored.
- The sample dashboard and the host CSV example in `Get-F5LtmInventory_v2.ps1` now use
  documentation-range addresses instead of private-range addresses.
- This changelog now follows Keep a Changelog.

## [1.0.1] - 2026-10-24

Applied to both `Get-F5LtmInventory.ps1` and `Get-F5LtmInventory_v2.ps1`.

### Fixed

- Follow iControl REST collection pagination, and fail explicitly on unsafe links, repeated pages,
  duplicate objects, or incomplete page sequences.
- Include nested `defaultsFrom` SSL profile certificate references in association and expiry reports.
- Keep the orphan-certificate CSV's 15-column schema consistent when no orphan rows are present.
