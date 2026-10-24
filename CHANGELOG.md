# Changelog

## 2026-10-24 — revision 1.0.1

Applied to both `Get-F5LtmInventory.ps1` and `Get-F5LtmInventory_v2.ps1`:

- Follow iControl REST collection pagination, and fail explicitly on unsafe links, repeated pages,
  duplicate objects, or incomplete page sequences.
- Include nested `defaultsFrom` SSL profile certificate references in association and expiry reports.
- Keep the orphan-certificate CSV's 15-column schema consistent when no orphan rows are present.

