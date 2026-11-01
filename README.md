# f5-cert-inventory-public

PowerShell inventory of F5 BIG-IP LTM virtual servers, pools, pool members and SSL certificates through iControl REST. It flags orphaned and soon-to-expire certificates and writes CSV reports plus a self-contained HTML dashboard. The scripts only read configuration; they do not change a device.

**Orphaned has a narrow meaning.** A certificate is "Associated" when an SSL profile attached to at least one virtual server references it. Anything else is reported as "Orphaned". Other BIG-IP features that can use a certificate are not scanned, so "orphaned" does not mean unused or safe to delete.

Current version: **1.0.1**. Both scripts carry the same version. See [CHANGELOG.md](CHANGELOG.md).

## Files

| File | Purpose |
| --- | --- |
| `Get-F5LtmInventory.ps1` | Parameter-driven. Pass `-BigIpHost` and a credential (`-Credential`, or `-CredentialFile`, or be prompted). |
| `Get-F5LtmInventory_v2.ps1` | Interactive. Run it with no arguments; it prompts for a host CSV, the BIG-IP username and password, whether to skip management-certificate verification, and the output folder. |
| `f5-hosts.example.csv` | Template host list for the interactive script. Copy it to `f5-hosts.csv` (git-ignored) and edit it. |
| `Sample-F5-Dashboard.html` | Sample dashboard built from placeholder data. |

The `_v2` suffix is part of the file name only; it is not a version number.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7.
- Network access to each BIG-IP management address.
- A BIG-IP account with a read-only role that can see all partitions.

## Run

```powershell
# Parameter-driven
.\Get-F5LtmInventory.ps1 -BigIpHost lb1.example.com -SkipCertificateCheck
.\Get-F5LtmInventory.ps1 -BigIpHost lb1,lb2 -CredentialFile .\f5.cred -OutputDirectory D:\inetpub\f5 -ExpiryWarningDays 60

# Interactive
.\Get-F5LtmInventory_v2.ps1
```

Run `Get-Help .\Get-F5LtmInventory.ps1 -Full` for every parameter. Certificates that expire in fewer than `-ExpiryWarningDays` days (default 90) are flagged.

## Host CSV (interactive script)

A header row, then one management name or address per row (`host` or `host:port`). The host column can be named Hostname, Host, BigIpHost, Name, Address, IP or ManagementIP; otherwise the first column is used. Blank rows, rows starting with `#` and duplicates are skipped. Other columns are ignored.

```csv
Hostname,Site
lb1.example.com,DC1
lb2.example.com,DC2
```

## Output

File names are fixed and overwritten on every run, so a link to a report never changes.

| File | Contents |
| --- | --- |
| `F5-Dashboard.html` | Self-contained dashboard (no external scripts, fonts or images) |
| `F5-VirtualServers.csv` | One row per virtual server |
| `F5-VS-Pool-Members.csv` | One row per virtual server and pool member |
| `F5-Pools.csv` | One row per pool |
| `F5-Certificates.csv` | Every certificate with association and expiry data |
| `F5-Orphaned-Certificates.csv` | Orphaned certificates, soonest expiry first |
| `F5-Inventory.json` | Everything above as JSON |
| `F5-Report.zip` | All of the above, plus a time-stamped copy in `archive\` |

## Security notes

- Reports contain real inventory data (hostnames, addresses, certificate subjects). They are git-ignored; never commit or publish them.
- `-CredentialFile` is created with `Get-Credential | Export-Clixml .\f5.cred`. It is protected for the exporting user on that machine only. Never commit it, and never put a password in a command line.
- `-SkipCertificateCheck` turns off verification of the BIG-IP management certificate. Use it only on a trusted management network.

## Versioning

[Semantic Versioning](https://semver.org/). Annotated tags `vMAJOR.MINOR.PATCH`.

- **Major:** different prompts, renamed or removed parameters, or changed output file names or columns.
- **Minor:** a new opt-in feature that leaves existing runs unchanged.
- **Patch:** a fix or change that does not affect behavior.

## Development and checks

`scripts/check.sh` runs a sanitization scan (credential-like files, private-key markers, literal secrets, tokens, addresses outside the documentation ranges, private-suffix hostnames), a version-sync check (both scripts, the CHANGELOG, this README and the newest tag must agree), and PSScriptAnalyzer when PowerShell 7 (`pwsh`) is installed. Only analyzer errors fail the check. There is no Pester suite yet.

```bash
bash scripts/check.sh            # everything available on this machine
bash scripts/check.sh --fast     # sanitization and version-sync only
bash scripts/check.sh --strict   # also fail if the analyzer cannot run (used by CI)
git config core.hooksPath .githooks   # enable the pre-commit hook, once per clone
```

Reviewed exceptions go in `.sanitize-allow` as `path-glob|check-id|reason`. Private terms that must never appear in this public repo belong in the git-ignored `.sanitize-deny.local`, never in a committed file. The scan is a safety net, not a guarantee: review every change before it is pushed to a public repository.

## License

No license file is present, so no license is granted.
