#Requires -Version 5.1

<#
.SYNOPSIS
    Inventories F5 BIG-IP LTM virtual servers, pools, pool members and SSL certificates through
    iControl REST, flags orphaned and soon-to-expire certificates, and writes CSV reports plus a
    self-contained HTML dashboard.

.DESCRIPTION
    Run it with no arguments. The script asks, in order, for:
      1. The CSV file listing the load balancers (see HOST CSV below)
      2. The BIG-IP username and password (the password is not echoed)
      3. Whether to skip verification of the BIG-IP management certificate
      4. The folder the reports are written to (Enter accepts the default shown)

    For every BIG-IP in the CSV the script collects:
      * Virtual servers (destination, status, default pool, iRules, SSL profiles)
      * Pools and their members (address, port, state, session)
      * Client-SSL and server-SSL profiles, and the certificate / chain / CA file each one references
      * Every certificate in the certificate store (/mgmt/tm/sys/file/ssl-cert)

    A certificate is "Associated" when it is referenced by an SSL profile that is attached to at
    least one virtual server. Anything else is "Orphaned". For orphans the report says whether an
    unattached SSL profile still references the certificate or nothing references it at all.

    Output files (fixed names, overwritten on every run so a SharePoint link never changes):
      F5-Dashboard.html            self-contained dashboard (no external scripts, fonts or images)
      F5-VirtualServers.csv        one row per virtual server
      F5-VS-Pool-Members.csv       one row per virtual server / pool member
      F5-Pools.csv                 one row per pool
      F5-Certificates.csv          every certificate with association and expiry data
      F5-Orphaned-Certificates.csv orphaned certificates, soonest expiry first
      F5-Inventory.json            everything above as JSON
      F5-Report.zip                all of the above, plus a time-stamped copy in .\archive

.NOTES
    HOST CSV
    A CSV with a header row. The host column may be named Hostname, Host, BigIpHost, Name,
    Address, IP or ManagementIP (case does not matter); if none of those is present the first
    column is used. Each value is a management name or address, optionally host:port.
    Blank rows, rows starting with # and duplicate hosts are skipped. Other columns are ignored,
    so a site or description column can stay in the file. Example:

        Hostname,Site
        lb1.example.com,DC1
        lb2.example.com,DC2
        10.20.30.40:8443,Lab

    The account entered at the prompt is used for every host in the file, so it needs a
    read-only role with access to all partitions on each of them.

.PARAMETER ExpiryWarningDays
    Certificates that expire in fewer days than this (including already expired ones) are flagged.
    Default 90.

.PARAMETER PublishPath
    Optional extra destination (UNC path, IIS folder, synced folder) the finished files are copied to.

.PARAMETER IncludeSystemCerts
    Count F5 default certificates (default.crt, ca-bundle.crt ...) in the orphan report and totals.
    They are always listed in the full certificate table, marked as system defaults.

.EXAMPLE
    .\Get-F5LtmInventory.ps1

    Prompts for the host CSV, username, password, certificate check and output folder.
#>
[CmdletBinding()]
param(
    # Optional tuning only. The host list, credentials, certificate check and output folder are prompted for.
    [string]$LoginProvider = 'tmos',
    [switch]$UseBasicAuth,

    [ValidateRange(1, 3650)]
    [int]$ExpiryWarningDays = 90,

    [string]$PublishPath,
    [switch]$IncludeSystemCerts,
    [string[]]$SystemCertNames = @('default.crt', 'ca-bundle.crt', 'f5-irule.crt', 'f5-ca-bundle.crt'),
    [int]$TimeoutSec = 120,
    [string]$Title = 'F5 BIG-IP LTM inventory and certificate report'
)

$ErrorActionPreference = 'Stop'
$script:IsCore = $PSVersionTable.PSVersion.Major -ge 6
$inv = [Globalization.CultureInfo]::InvariantCulture
$nowUtc = [DateTime]::UtcNow
$stamp = $nowUtc.ToString('yyyyMMdd-HHmmss', $inv)

# =====================================================================================
#  Generic helpers
# =====================================================================================

function Esc {
    param($Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Join-Text {
    param($Items, [string]$Separator = '; ')
    (@($Items) | Where-Object { $null -ne $_ -and "$_" -ne '' }) -join $Separator
}

# Drop the /Common/ prefix so names read the way they do in tmsh.
function Short {
    param([string]$Path)
    if ($Path) { return ($Path -replace '^/Common/', '') }
    return ''
}

function Format-Pct {
    param([double]$Value)
    return [string]::Format($inv, '{0:0.#}', $Value)
}

function Get-Plural {
    param([int]$Count, [string]$Singular, [string]$Plural)
    if ($Count -eq 1) { return $Singular }
    if ($Plural) { return $Plural }
    return "${Singular}s"
}

# =====================================================================================
#  Interactive prompts
# =====================================================================================

# Strips surrounding quotes and whitespace, so a path pasted from Explorer's "Copy as path" works.
function Get-CleanPath {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return $Text.Trim().Trim('"', "'").Trim()
}

function Read-YesNo {
    param([string]$Prompt, [bool]$Default = $false)
    $hint = if ($Default) { '[Y/n]' } else { '[y/N]' }
    while ($true) {
        $answer = (Read-Host "$Prompt $hint").Trim()
        if ($answer -eq '') { return $Default }
        switch -Regex ($answer) {
            '^(y|yes)$' { return $true }
            '^(n|no)$'  { return $false }
        }
        Write-Host '  Please answer y or n.' -ForegroundColor Yellow
    }
}

# Reads the load balancer list from a CSV and returns the unique host values.
function Read-HostCsv {
    param([string]$Path)
    $rows = @(Import-Csv -LiteralPath $Path)
    if ($rows.Count -eq 0) { throw "The CSV '$Path' has a header row but no hosts." }

    $columns = @($rows[0].PSObject.Properties.Name)
    $preferred = 'Hostname', 'Host', 'BigIpHost', 'BigIp', 'Name', 'Address', 'IP', 'ManagementIP', 'MgmtIP'
    $column = $null
    foreach ($p in $preferred) {
        $match = $columns | Where-Object { $_.Trim() -ieq $p } | Select-Object -First 1
        if ($match) { $column = $match; break }
    }
    if (-not $column) {
        $column = $columns[0]
        Write-Host "  No Hostname/Host/Address column found; using the first column '$column'." -ForegroundColor Yellow
    }

    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $hosts = New-Object System.Collections.Generic.List[string]
    foreach ($r in $rows) {
        $value = ([string]$r.$column).Trim()
        if ($value -eq '' -or $value.StartsWith('#')) { continue }
        $value = $value -replace '^https?://', '' -replace '/.*$', ''
        if ($seen.Add($value)) { $hosts.Add($value) }
    }
    if ($hosts.Count -eq 0) { throw "No hosts found in column '$column' of '$Path'." }
    return $hosts.ToArray()
}

function Read-HostList {
    $default = ''
    $baseDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $candidate = Join-Path $baseDir 'f5-hosts.csv'
    if (Test-Path -LiteralPath $candidate -PathType Leaf) { $default = $candidate }

    while ($true) {
        $prompt = 'Path to the CSV of load balancer hostnames'
        if ($default) { $prompt += " [$default]" }
        $path = Get-CleanPath (Read-Host $prompt)
        if ($path -eq '' -and $default) { $path = $default }
        if ($path -eq '') { Write-Host '  A CSV path is required.' -ForegroundColor Yellow; continue }
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            Write-Host "  File not found: $path" -ForegroundColor Yellow
            continue
        }
        try {
            $hosts = Read-HostCsv -Path $path
            Write-Host "  $($hosts.Count) $(Get-Plural $hosts.Count 'load balancer'): $($hosts -join ', ')" -ForegroundColor Cyan
            return $hosts
        }
        catch {
            Write-Host "  $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

function Read-F5Credential {
    while ($true) {
        $user = (Read-Host 'BIG-IP username').Trim()
        if ($user -ne '') { break }
        Write-Host '  A username is required.' -ForegroundColor Yellow
    }
    while ($true) {
        $pass = Read-Host 'BIG-IP password' -AsSecureString
        if ($pass.Length -gt 0) { break }
        Write-Host '  A password is required.' -ForegroundColor Yellow
    }
    return New-Object System.Management.Automation.PSCredential($user, $pass)
}

function Read-OutputDirectory {
    $baseDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $default = Join-Path $baseDir 'F5-Reports'
    while ($true) {
        $path = Get-CleanPath (Read-Host "Output folder for the reports [$default]")
        if ($path -eq '') { $path = $default }
        try {
            if (-not (Test-Path -LiteralPath $path)) {
                New-Item -ItemType Directory -Path $path -Force | Out-Null
                Write-Host "  Created $path" -ForegroundColor Cyan
            }
            elseif (-not (Test-Path -LiteralPath $path -PathType Container)) {
                Write-Host "  $path is a file, not a folder." -ForegroundColor Yellow
                continue
            }
            # Prove the folder is writable before spending time collecting.
            $probe = Join-Path $path ('.write-test-' + [guid]::NewGuid().ToString('N'))
            [System.IO.File]::WriteAllText($probe, '')
            Remove-Item -LiteralPath $probe -Force
            return (Resolve-Path -LiteralPath $path).Path
        }
        catch {
            Write-Host "  Cannot write to ${path}: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

# =====================================================================================
#  iControl REST plumbing
# =====================================================================================

function Initialize-Tls {
    if (-not $script:IsCore) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        if ($SkipCertificateCheck) {
            if (-not ('F5TrustAllCertsPolicy' -as [type])) {
                Add-Type -TypeDefinition @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class F5TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
"@
            }
            [Net.ServicePointManager]::CertificatePolicy = New-Object F5TrustAllCertsPolicy
        }
    }
}

function Invoke-F5Api {
    param(
        [Parameter(Mandatory = $true)][string]$Device,
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Method = 'GET',
        [hashtable]$Headers = @{},
        $Body
    )
    $params = @{
        Uri             = "https://$Device$Path"
        Method          = $Method
        Headers         = $Headers
        UseBasicParsing = $true
        TimeoutSec      = $TimeoutSec
    }
    if ($null -ne $Body) {
        $params.Body = ($Body | ConvertTo-Json -Compress)
        $params.ContentType = 'application/json'
    }
    if ($script:IsCore -and $SkipCertificateCheck) { $params.SkipCertificateCheck = $true }

    try {
        # Invoke-WebRequest + ConvertFrom-Json avoids the 2 MB JSON limit Invoke-RestMethod has in Windows PowerShell 5.1.
        $response = Invoke-WebRequest @params
    }
    catch {
        $detail = $_.Exception.Message
        $webResponse = $_.Exception.Response
        if ($webResponse -and -not $script:IsCore) {
            try {
                $reader = New-Object System.IO.StreamReader($webResponse.GetResponseStream())
                $detail += ' ' + $reader.ReadToEnd()
            } catch { }
        }
        elseif ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            $detail += ' ' + $_.ErrorDetails.Message
        }
        throw "iControl REST $Method https://$Device$Path failed: $detail"
    }
    if ($response.Content) { return ($response.Content | ConvertFrom-Json) }
    return $null
}

function Connect-F5 {
    param([string]$Device, [pscredential]$Cred)
    $password = $Cred.GetNetworkCredential().Password
    if ($UseBasicAuth) {
        $pair = '{0}:{1}' -f $Cred.UserName, $password
        $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($pair))
        return [pscustomobject]@{ Headers = @{ Authorization = "Basic $b64" }; Token = $null }
    }
    $login = Invoke-F5Api -Device $Device -Path '/mgmt/shared/authn/login' -Method POST -Body @{
        username          = $Cred.UserName
        password          = $password
        loginProviderName = $LoginProvider
    }
    if (-not $login.token.token) { throw "Login to $Device did not return a token." }
    return [pscustomobject]@{ Headers = @{ 'X-F5-Auth-Token' = $login.token.token }; Token = $login.token.token }
}

function Disconnect-F5 {
    param([string]$Device, $Session)
    if ($Session -and $Session.Token) {
        try {
            Invoke-F5Api -Device $Device -Path "/mgmt/shared/authz/tokens/$($Session.Token)" -Method DELETE -Headers $Session.Headers | Out-Null
        } catch { Write-Verbose "Could not delete auth token on ${Device}: $_" }
    }
}

function Get-F5Items {
    param([string]$Device, [hashtable]$Headers, [string]$Path)
    $r = Invoke-F5Api -Device $Device -Path $Path -Headers $Headers
    if ($r -and $r.items) { return @($r.items) }
    return @()
}

# Returns the items of an expanded sub-collection, or fetches the sub-collection when -Fetch is set.
function Get-SubItems {
    param([string]$Device, [hashtable]$Headers, $Reference, [switch]$Fetch)
    if (-not $Reference) { return @() }
    if ($Reference.items) { return @($Reference.items) }
    if ($Fetch -and $Reference.link) {
        $path = $Reference.link -replace '^https://[^/]+', ''
        return @(Get-F5Items -Device $Device -Headers $Headers -Path $path)
    }
    return @()
}

# =====================================================================================
#  Parsing helpers
# =====================================================================================

function Split-Destination {
    param([string]$Destination)
    # IPv4 uses "addr:port", IPv6 uses "addr.port"; a partition prefix may be present.
    if ($Destination -match '^(?:/.+/)?(?<addr>[^/]+?)[:.](?<port>\d+|any)$') {
        return [pscustomobject]@{ Address = $Matches['addr']; Port = $Matches['port'] }
    }
    return [pscustomobject]@{ Address = $Destination; Port = '' }
}

function Get-CertExpiry {
    param($Cert)
    if ($Cert.expirationDate) {
        return (New-Object DateTime 1970, 1, 1, 0, 0, 0, ([DateTimeKind]::Utc)).AddSeconds([double]$Cert.expirationDate)
    }
    if ($Cert.expirationString) {
        $s = (($Cert.expirationString -replace '\s+', ' ') -replace ' GMT$', '').Trim()
        try {
            return [DateTime]::ParseExact($s, 'MMM d HH:mm:ss yyyy', $inv, [Globalization.DateTimeStyles]'AssumeUniversal,AdjustToUniversal')
        } catch { }
    }
    return $null
}

function Get-CommonName {
    param([string]$Dn)
    if ($Dn -match '(?:^|[,/\s])CN\s*=\s*(?<cn>[^,/]+)') { return $Matches['cn'].Trim() }
    return $Dn
}

function Get-ExpiryStatus {
    param($Days)
    if ($null -eq $Days) { return 'Unknown' }
    if ($Days -lt 0) { return 'Expired' }
    if ($Days -lt [math]::Min(30, $ExpiryWarningDays)) { return 'Critical' }
    if ($Days -lt $ExpiryWarningDays) { return 'Expiring' }
    return 'OK'
}

# Every certificate-like file an SSL profile points at: cert, chain, certKeyChain entries, CA files.
function Get-ProfileCertRefs {
    param($SslProfile)
    $sources = @(
        [pscustomobject]@{ Path = $SslProfile.cert; Role = 'Certificate' }
        [pscustomobject]@{ Path = $SslProfile.chain; Role = 'Chain' }
    )
    foreach ($ck in @($SslProfile.certKeyChain)) {
        if ($ck) {
            $sources += [pscustomobject]@{ Path = $ck.cert; Role = 'Certificate' }
            $sources += [pscustomobject]@{ Path = $ck.chain; Role = 'Chain' }
        }
    }
    foreach ($field in 'caFile', 'trustedCertAuthorities', 'advertisedCertAuthorities') {
        $sources += [pscustomobject]@{ Path = $SslProfile.($field); Role = 'CA file' }
    }
    return @($sources | Where-Object { $_.Path -and $_.Path -ne 'none' } | Sort-Object Path, Role -Unique)
}

# =====================================================================================
#  Data collection for one BIG-IP
# =====================================================================================

function Get-F5Data {
    param([string]$Device, [hashtable]$Headers)

    # ---- SSL profiles --------------------------------------------------------------
    Write-Host '  SSL profiles'
    $sslProfiles = @{}
    foreach ($type in 'client-ssl', 'server-ssl') {
        foreach ($p in @(Get-F5Items -Device $Device -Headers $Headers -Path "/mgmt/tm/ltm/profile/$type")) {
            $full = if ($p.fullPath) { $p.fullPath } else { "/$($p.partition)/$($p.name)" }
            $sslProfiles[$full] = [pscustomobject]@{
                FullPath = $full
                Type     = $type
                Refs     = @(Get-ProfileCertRefs -SslProfile $p)
            }
        }
    }

    # ---- Certificate store ---------------------------------------------------------
    Write-Host '  Certificate store'
    $certs = @{}
    foreach ($c in @(Get-F5Items -Device $Device -Headers $Headers -Path '/mgmt/tm/sys/file/ssl-cert')) {
        $full = if ($c.fullPath) { $c.fullPath } else { "/$($c.partition)/$($c.name)" }
        $exp = Get-CertExpiry -Cert $c
        $days = $null
        $expText = ''
        if ($exp) {
            $days = [int][math]::Floor(($exp - $nowUtc).TotalDays)
            $expText = $exp.ToString('yyyy-MM-dd HH:mm', $inv)
        }
        $keyKind = (([string]$c.keyType) -replace '-public$', '').ToUpper()
        if ($c.certificateKeyCurveName -and $c.certificateKeyCurveName -ne 'none') {
            $keyInfo = "$keyKind $($c.certificateKeyCurveName)"
        } else {
            $keyInfo = "$keyKind $($c.certificateKeySize)".Trim()
        }
        $status = Get-ExpiryStatus -Days $days
        $certs[$full] = [pscustomobject]@{
            Device                 = $Device
            Name                   = Short $full
            Partition              = $c.partition
            FullPath               = $full
            CommonName             = Get-CommonName -Dn $c.subject
            Subject                = $c.subject
            IssuerCN               = Get-CommonName -Dn $c.issuer
            Issuer                 = $c.issuer
            SubjectAltNames        = $c.subjectAlternativeName
            Key                    = $keyInfo
            ExpirationUtc          = $expText
            DaysToExpiry           = $days
            ExpiryStatus           = $status
            ExpiresWithinThreshold = if ($null -ne $days -and $days -lt $ExpiryWarningDays) { 'Yes' } else { 'No' }
            Association            = 'Orphaned'
            OrphanReason           = ''
            IsSystemDefault        = ($c.partition -eq 'Common' -and ($SystemCertNames -contains $c.name))
            IsBundle               = ($c.isBundle -eq 'true' -or $c.isBundle -eq $true)
            VirtualServerCount     = 0
            VirtualServers         = ''
            SslProfiles            = ''
        }
    }

    # ---- Pools and members ---------------------------------------------------------
    Write-Host '  Pools and members'
    $poolItems = @(Get-F5Items -Device $Device -Headers $Headers -Path '/mgmt/tm/ltm/pool?expandSubcollections=true')
    $poolFetch = ($poolItems.Count -gt 0) -and -not ($poolItems | Where-Object { $_.membersReference -and $_.membersReference.items } | Select-Object -First 1)
    $pools = @{}
    foreach ($p in $poolItems) {
        $full = if ($p.fullPath) { $p.fullPath } else { "/$($p.partition)/$($p.name)" }
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($m in @(Get-SubItems -Device $Device -Headers $Headers -Reference $p.membersReference -Fetch:$poolFetch)) {
            $port = ''
            if ($m.name -match '[:.](\d+|any)$') { $port = $Matches[1] }
            $state = switch ([string]$m.state) {
                'up'        { 'Up' }
                'down'      { 'Down' }
                'unchecked' { 'Unchecked' }
                'user-down' { 'Disabled' }
                default     { 'Unknown' }
            }
            if ($m.session -eq 'user-disabled') { $state = 'Disabled' }
            $list.Add([pscustomobject]@{
                Device        = $Device
                Pool          = Short $full
                Name          = $m.name
                Address       = $m.address
                Port          = $port
                Status        = $state
                Session       = $m.session
                Ratio         = $m.ratio
                PriorityGroup = $m.priorityGroup
            })
        }
        $up = @($list | Where-Object { $_.Status -eq 'Up' }).Count
        $pools[$full] = [pscustomobject]@{
            Device        = $Device
            Name          = Short $full
            Partition     = $p.partition
            FullPath      = $full
            LoadBalancing = $p.loadBalancingMode
            Monitor       = ([string]$p.monitor) -replace '/Common/', ''
            MemberCount   = $list.Count
            MembersUp     = $up
            Members       = Join-Text ($list | ForEach-Object { "$($_.Name) ($($_.Status))" })
            UsedBy        = ''
            Description   = $p.description
            MemberList    = $list.ToArray()
        }
    }

    # ---- Virtual servers -----------------------------------------------------------
    Write-Host '  Virtual servers'
    $vsItems = @(Get-F5Items -Device $Device -Headers $Headers -Path '/mgmt/tm/ltm/virtual?expandSubcollections=true')
    $vsFetch = ($vsItems.Count -gt 0) -and -not ($vsItems | Where-Object { $_.profilesReference -and $_.profilesReference.items } | Select-Object -First 1)
    $vsRows = New-Object System.Collections.Generic.List[object]
    $bindings = New-Object System.Collections.Generic.List[object]
    $poolUsedBy = @{}

    foreach ($v in $vsItems) {
        $full = if ($v.fullPath) { $v.fullPath } else { "/$($v.partition)/$($v.name)" }
        $dest = Split-Destination -Destination $v.destination
        $clientProfiles = @()
        $serverProfiles = @()
        $myBindings = @()

        foreach ($pr in @(Get-SubItems -Device $Device -Headers $Headers -Reference $v.profilesReference -Fetch:$vsFetch)) {
            $pf = if ($pr.fullPath) { $pr.fullPath } else { "/$($pr.partition)/$($pr.name)" }
            if (-not $sslProfiles.ContainsKey($pf)) { continue }
            $sp = $sslProfiles[$pf]
            if ($sp.Type -eq 'client-ssl') { $clientProfiles += (Short $pf) } else { $serverProfiles += (Short $pf) }
            foreach ($ref in $sp.Refs) {
                $cert = $certs[$ref.Path]
                $myBindings += [pscustomobject]@{
                    Device        = $Device
                    VirtualServer = Short $full
                    Profile       = Short $pf
                    ProfileType   = $sp.Type
                    Role          = $ref.Role
                    CertPath      = $ref.Path
                    Certificate   = Short $ref.Path
                    ExpirationUtc = if ($cert) { $cert.ExpirationUtc } else { '' }
                    DaysToExpiry  = if ($cert) { $cert.DaysToExpiry } else { $null }
                    ExpiryStatus  = if ($cert) { $cert.ExpiryStatus } else { 'Unknown' }
                }
            }
        }
        foreach ($b in $myBindings) { $bindings.Add($b) }

        $poolPath = [string]$v.pool
        $memberList = @()
        if ($poolPath -and $pools.ContainsKey($poolPath)) { $memberList = @($pools[$poolPath].MemberList) }
        if ($poolPath) {
            if (-not $poolUsedBy.ContainsKey($poolPath)) { $poolUsedBy[$poolPath] = @() }
            $poolUsedBy[$poolPath] += (Short $full)
        }

        $soonest = $myBindings | Where-Object { $null -ne $_.DaysToExpiry } | Sort-Object DaysToExpiry | Select-Object -First 1
        $soonestDate = ''
        $soonestDays = $null
        if ($soonest) { $soonestDate = $soonest.ExpirationUtc; $soonestDays = $soonest.DaysToExpiry }

        $vsStatus = 'Enabled'
        if ($v.disabled -eq $true) { $vsStatus = 'Disabled' }
        $uniqueCerts = $myBindings | ForEach-Object { $_.Certificate } | Select-Object -Unique
        $rules = $v.rules | ForEach-Object { Short $_ }

        $vsRows.Add([pscustomobject]@{
            Device            = $Device
            Name              = Short $full
            Partition         = $v.partition
            FullPath          = $full
            Address           = $dest.Address
            Port              = $dest.Port
            Protocol          = $v.ipProtocol
            Status            = $vsStatus
            Pool              = Short $poolPath
            PoolMemberCount   = $memberList.Count
            PoolMembers       = Join-Text ($memberList | ForEach-Object { "$($_.Name) ($($_.Status))" })
            ClientSslProfiles = Join-Text $clientProfiles
            ServerSslProfiles = Join-Text $serverProfiles
            Certificates      = Join-Text $uniqueCerts
            SoonestCertExpiry = $soonestDate
            SoonestCertDays   = $soonestDays
            IRules            = Join-Text $rules
            SourceAddress     = $v.source
            SnatType          = $v.sourceAddressTranslation.type
            Description       = $v.description
            MemberList        = $memberList
            Bindings          = $myBindings
        })
    }
    foreach ($key in $poolUsedBy.Keys) {
        if ($pools.ContainsKey($key)) { $pools[$key].UsedBy = Join-Text ($poolUsedBy[$key] | Sort-Object -Unique) }
    }

    # ---- Classify certificates -----------------------------------------------------
    $bindByCert = @{}
    foreach ($b in $bindings) {
        if (-not $bindByCert.ContainsKey($b.CertPath)) { $bindByCert[$b.CertPath] = @() }
        $bindByCert[$b.CertPath] += $b
    }
    $profilesByCert = @{}
    foreach ($sp in $sslProfiles.Values) {
        foreach ($ref in $sp.Refs) {
            if (-not $profilesByCert.ContainsKey($ref.Path)) { $profilesByCert[$ref.Path] = @() }
            $profilesByCert[$ref.Path] += (Short $sp.FullPath)
        }
    }
    foreach ($c in $certs.Values) {
        $vsNames = @($bindByCert[$c.FullPath] | ForEach-Object { $_.VirtualServer } | Select-Object -Unique | Sort-Object)
        $profNames = @($profilesByCert[$c.FullPath] | Select-Object -Unique | Sort-Object)
        $c.VirtualServerCount = $vsNames.Count
        $c.VirtualServers = Join-Text $vsNames
        $c.SslProfiles = Join-Text $profNames
        if ($vsNames.Count -gt 0) {
            $c.Association = 'Associated'
        }
        elseif ($profNames.Count -gt 0) {
            $c.OrphanReason = 'Referenced only by SSL profile(s) not attached to a virtual server: ' + (Join-Text $profNames ', ')
        }
        else {
            $c.OrphanReason = 'Not referenced by any SSL profile'
        }
    }

    return [pscustomobject]@{
        VirtualServers = $vsRows.ToArray()
        Pools          = @($pools.Values)
        Certificates   = @($certs.Values)
    }
}

# =====================================================================================
#  HTML builders
# =====================================================================================

function New-MemberListHtml {
    param($Members)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<ul class='members'>")
    foreach ($m in $Members) {
        $cls = ([string]$m.Status).ToLower()
        $label = [string]$m.Name
        if ($m.Address -and -not $label.StartsWith([string]$m.Address)) { $label += " ($($m.Address))" }
        [void]$sb.Append("<li><span class='led $cls' aria-hidden='true'></span><code>$(Esc $label)</code><span class='state'>$(Esc $m.Status)</span></li>")
    }
    [void]$sb.Append('</ul>')
    return $sb.ToString()
}

function Get-DaysBadgeHtml {
    param($Days, [string]$Status)
    if ($null -eq $Days) { return "<span class='badge s-none'>Unknown</span>" }
    $cls = switch ($Status) { 'Expired' { 's-expired' } 'Critical' { 's-crit' } 'Expiring' { 's-soon' } default { 's-ok' } }
    $text = if ($Days -lt 0) { "Expired $([math]::Abs($Days)) d ago" } else { "$Days d" }
    return "<span class='badge $cls'>$text</span>"
}

function Get-BindingLabel {
    param($Binding)
    if ($Binding.ProfileType -eq 'server-ssl') { return "server-side $($Binding.Role.ToLower())" }
    if ($Binding.Role -ne 'Certificate') { return $Binding.Role.ToLower() }
    return ''
}

function New-TableHtml {
    param([string]$Id, [object[]]$Rows, [object[]]$Columns, [string]$Empty)
    if (-not $Rows -or $Rows.Count -eq 0) { return "<p class='empty'>$(Esc $Empty)</p>" }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<div class='tablewrap'><table class='data' id='tbl-$Id'><thead><tr>")
    foreach ($c in $Columns) { [void]$sb.Append("<th scope='col'>$(Esc $c.Header)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in $Rows) {
        [void]$sb.Append('<tr>')
        foreach ($c in $Columns) {
            if ($c.Plain) { $plain = & $c.Plain $r } else { $plain = $r.($c.Prop) }
            if ($plain -is [array]) { $plain = $plain -join '; ' }
            if ($c.Html) { $html = & $c.Html $r } else { $html = Esc $plain }
            [void]$sb.Append("<td data-v=""$(Esc $plain)"">$html</td>")
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    return $sb.ToString()
}

function New-SectionHtml {
    param([string]$Id, [string]$Slug, [string]$Heading, [int]$Count, [string]$NoteHtml, [string]$TableHtml)
    return @"
<section id="$Id" data-table="$Slug">
<h2>$(Esc $Heading)<span class="count">$Count</span></h2>
<p class="note">$NoteHtml</p>
<div class="toolbar js-only">
<label>Filter <input type="search" class="filter" placeholder="Type to filter rows"></label>
<span class="shown" aria-live="polite"></span>
<button type="button" class="export">Export CSV</button>
</div>
$TableHtml
</section>
"@
}

$HtmlTemplate = @'
<!DOCTYPE html>
<html lang="en" class="no-js">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%%TITLE%%</title>
<style>
:root{--ink:#1d2b36;--muted:#586976;--rule:#d3dbe2;--wash:#f2f5f7;--accent:#0c6a87;--ok:#17734a;--soon:#9a5b00;--crit:#c9302c;--expired:#8e1b2e;--orphan:#5d4e9e}
*{box-sizing:border-box}
html{color-scheme:light}
body{margin:0;background:#fff;color:var(--ink);font:14px/1.5 "Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif}
main{max-width:1320px;margin:0 auto;padding:24px 28px 48px}
code{font-family:"Cascadia Mono",Consolas,"SF Mono",ui-monospace,monospace;font-size:12.5px}
h1{font-size:20px;font-weight:600;margin:0 0 4px}
.meta{margin:0;color:var(--muted)}
.warn{margin:16px 0 0;padding:8px 12px;border-left:4px solid var(--soon);background:#fff7e6}
.lead{margin:28px 0 24px;max-width:72ch}
.headline{font-size:28px;line-height:1.25;font-weight:600;margin:0 0 8px;letter-spacing:-.01em}
.subline{margin:0;color:var(--muted);font-size:15px}
.overview{display:grid;grid-template-columns:minmax(0,1.6fr) minmax(260px,1fr);gap:44px;align-items:start;padding:22px 0;border-top:1px solid var(--rule);border-bottom:1px solid var(--rule)}
.overview h2{font-size:15px;margin:0 0 12px}
.runway{display:grid;gap:8px}
.rw-row{display:grid;grid-template-columns:130px minmax(0,1fr) 200px;gap:12px;align-items:center}
.rw-label{font-weight:500}
.rw-bar{display:flex;height:18px;background:var(--wash)}
.rw-bar i{display:block;height:100%}
.rw-bar .use{background:var(--c)}
.rw-bar .orph{background:repeating-linear-gradient(135deg,var(--c) 0 3px,#fff 3px 6px);box-shadow:inset 0 0 0 1px var(--c)}
.rw-n{color:var(--muted);font-size:13px}
.rw-n b{color:var(--ink);font-weight:600}
.legend{margin:12px 0 0;color:var(--muted);font-size:13px}
.s-expired{--c:var(--expired)}.s-crit{--c:var(--crit)}.s-soon{--c:var(--soon)}.s-ok{--c:var(--ok)}.s-none{--c:var(--muted)}
.figures{margin:0;display:grid;grid-template-columns:1fr auto;gap:0 20px}
.figures div{display:contents}
.figures dt,.figures dd{padding:6px 0;border-bottom:1px solid var(--rule)}
.figures dt{color:var(--muted)}
.figures dd{margin:0;text-align:right;font-weight:600;font-variant-numeric:tabular-nums}
.figures .hot dt,.figures .hot dd{color:var(--crit)}
.downloads{margin:16px 0 0;color:var(--muted)}
a{color:var(--accent)}
nav{display:flex;flex-wrap:wrap;gap:4px 28px;margin:22px 0 0;padding-bottom:6px}
nav a{text-decoration:none;padding:4px 0;border-bottom:2px solid transparent;font-weight:500}
nav a:hover,nav a:focus-visible{border-bottom-color:var(--accent)}
section{margin-top:36px}
h2{font-size:18px;font-weight:600;margin:0 0 4px}
h2 .count{color:var(--muted);font-weight:400;margin-left:8px}
.note{margin:0 0 12px;color:var(--muted);max-width:100ch}
.empty{padding:14px 0;color:var(--muted)}
.toolbar{gap:16px;align-items:center;flex-wrap:wrap;margin:0 0 8px}
.js-only{display:none}.js .js-only{display:flex}
.toolbar label{color:var(--muted)}
input[type=search]{font:inherit;padding:4px 8px;border:1px solid var(--rule);border-radius:3px;min-width:240px}
button{font:inherit;padding:4px 12px;border:1px solid var(--accent);background:#fff;color:var(--accent);border-radius:3px;cursor:pointer}
button:hover{background:var(--accent);color:#fff}
.shown{color:var(--muted);margin-right:auto}
.tablewrap{overflow-x:auto;border-top:1px solid var(--ink)}
table.data{border-collapse:collapse;width:100%;min-width:880px}
table.data th{text-align:left;font-weight:600;padding:8px 12px;border-bottom:1px solid var(--rule);background:var(--wash);white-space:nowrap}
table.data td{padding:8px 12px;border-bottom:1px solid var(--rule);vertical-align:top}
table.data tbody tr:hover{background:#f8fafb}
.js table.data th{cursor:pointer;user-select:none}
th[aria-sort=ascending]::after{content:" \25B2";font-size:10px}
th[aria-sort=descending]::after{content:" \25BC";font-size:10px}
.badge{display:inline-block;padding:0 7px;border:1px solid var(--c,var(--muted));color:var(--c,var(--muted));border-radius:3px;font-size:12px;line-height:18px;font-weight:600;white-space:nowrap}
.badge.s-expired{background:var(--expired);color:#fff}
.u-use{--c:var(--accent)}.u-orphan{--c:var(--orphan)}
.muted{color:var(--muted)}
.certline{margin:0 0 3px}
.certline .role{color:var(--muted);font-size:12px}
details summary{cursor:pointer;color:var(--accent)}
ul.members{list-style:none;margin:6px 0 0;padding:0}
ul.members li{display:flex;gap:8px;align-items:center;padding:1px 0}
.led{width:9px;height:9px;border-radius:50%;background:var(--muted);flex:none}
.led.up{background:var(--ok)}.led.down{background:var(--crit)}.led.disabled{background:#fff;border:2px solid var(--muted)}
.state{color:var(--muted);font-size:12px}
footer{margin-top:40px;padding-top:14px;border-top:1px solid var(--rule);color:var(--muted);max-width:100ch}
footer p{margin:0 0 6px}
a:focus-visible,button:focus-visible,input:focus-visible,summary:focus-visible,th:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
@media (max-width:860px){main{padding:16px}.overview{grid-template-columns:1fr;gap:24px}.rw-row{grid-template-columns:110px minmax(0,1fr)}.rw-n{grid-column:1/-1}.headline{font-size:22px}}
</style>
</head>
<body>
<main>
<header>
<h1>%%TITLE%%</h1>
<p class="meta">%%META%%</p>
</header>
%%WARN%%
<div class="lead">
<p class="headline">%%HEADLINE%%</p>
<p class="subline">%%SUBLINE%%</p>
</div>
<div class="overview">
<div>
<h2>Certificate expiry runway</h2>
<div class="runway">
%%RUNWAY%%
</div>
<p class="legend">Solid bars are certificates bound to a virtual server. Striped bars are orphaned certificates. %%RUNWAYNOTE%%</p>
</div>
<dl class="figures">
%%FIGURES%%
</dl>
</div>
<p class="downloads">%%DOWNLOADS%%</p>
<nav aria-label="Report sections">
%%NAV%%
</nav>
%%SECTIONS%%
<footer>
%%FOOTER%%
</footer>
</main>
<script>
(function () {
  document.documentElement.className = 'js';
  var collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });
  function cellValue(td) { var v = td.getAttribute('data-v'); return v === null ? td.textContent.trim() : v; }
  function isNum(s) { return /^-?\d+(\.\d+)?$/.test(s); }
  function csvEscape(s) { return '"' + String(s).replace(/"/g, '""') + '"'; }

  Array.prototype.forEach.call(document.querySelectorAll('section[data-table]'), function (sec) {
    var tbl = sec.querySelector('table.data');
    if (!tbl) { var tb = sec.querySelector('.toolbar'); if (tb) tb.style.display = 'none'; return; }
    var body = tbl.tBodies[0];
    var rows = Array.prototype.slice.call(body.rows);
    var ths = tbl.tHead.rows[0].cells;
    var input = sec.querySelector('.filter');
    var shown = sec.querySelector('.shown');
    var exportBtn = sec.querySelector('.export');

    function updateCount() {
      var n = 0;
      rows.forEach(function (r) { if (!r.hidden) n++; });
      shown.textContent = 'Showing ' + n + ' of ' + rows.length;
    }

    rows.forEach(function (r) {
      r._text = (Array.prototype.map.call(r.cells, cellValue).join(' ') + ' ' + r.textContent).toLowerCase();
    });

    input.addEventListener('input', function () {
      var q = input.value.trim().toLowerCase();
      rows.forEach(function (r) { r.hidden = q !== '' && r._text.indexOf(q) === -1; });
      updateCount();
    });

    Array.prototype.forEach.call(ths, function (th, i) {
      th.tabIndex = 0;
      function sortBy() {
        var dir = th.getAttribute('aria-sort') === 'ascending' ? 'descending' : 'ascending';
        Array.prototype.forEach.call(ths, function (o) { o.removeAttribute('aria-sort'); });
        th.setAttribute('aria-sort', dir);
        var f = dir === 'ascending' ? 1 : -1;
        rows.sort(function (a, b) {
          var x = cellValue(a.cells[i]), y = cellValue(b.cells[i]);
          if (x === '' && y !== '') return 1;
          if (y === '' && x !== '') return -1;
          if (isNum(x) && isNum(y)) return (parseFloat(x) - parseFloat(y)) * f;
          return collator.compare(x, y) * f;
        });
        rows.forEach(function (r) { body.appendChild(r); });
      }
      th.addEventListener('click', sortBy);
      th.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); sortBy(); }
      });
    });

    exportBtn.addEventListener('click', function () {
      var out = [Array.prototype.map.call(ths, function (th) { return csvEscape(th.textContent.trim()); }).join(',')];
      rows.forEach(function (r) {
        if (r.hidden) return;
        out.push(Array.prototype.map.call(r.cells, function (td) { return csvEscape(cellValue(td)); }).join(','));
      });
      var blob = new Blob(['\uFEFF' + out.join('\r\n')], { type: 'text/csv;charset=utf-8' });
      var a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = sec.getAttribute('data-table') + '.csv';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
    });

    updateCount();
  });
})();
</script>
</body>
</html>
'@

# =====================================================================================
#  Main
# =====================================================================================

Write-Host ''
Write-Host $Title -ForegroundColor White
Write-Host ''

# 1. Load balancers
$BigIpHost = @(Read-HostList)

# 2. Credentials (used for every host in the CSV)
$Credential = Read-F5Credential

# 3. Certificate verification
$SkipCertificateCheck = Read-YesNo -Prompt 'Skip verification of the BIG-IP management certificate (self-signed or untrusted)?' -Default $false
if ($SkipCertificateCheck) {
    Write-Host '  Certificate verification is OFF for this run.' -ForegroundColor Yellow
}

# 4. Output folder
$OutputDirectory = Read-OutputDirectory
$archiveDir = Join-Path $OutputDirectory 'archive'
if (-not (Test-Path -LiteralPath $archiveDir)) { New-Item -ItemType Directory -Path $archiveDir -Force | Out-Null }

Write-Host ''
Initialize-Tls

$collected = @()
$okDevices = @()
$failures = @()
foreach ($device in $BigIpHost) {
    Write-Host "Collecting from $device"
    $session = $null
    try {
        $session = Connect-F5 -Device $device -Cred $Credential
        $collected += Get-F5Data -Device $device -Headers $session.Headers
        $okDevices += $device
    }
    catch {
        Write-Warning "Skipping ${device}: $($_.Exception.Message)"
        $failures += [pscustomobject]@{ Device = $device; Reason = $_.Exception.Message }
    }
    finally {
        Disconnect-F5 -Device $device -Session $session
    }
}
if ($okDevices.Count -eq 0) { throw 'None of the BIG-IP devices could be queried.' }

$vsAll = @($collected | ForEach-Object { $_.VirtualServers } | Sort-Object Device, Name)
$poolAll = @($collected | ForEach-Object { $_.Pools } | Sort-Object Device, Name)
$certAll = @($collected | ForEach-Object { $_.Certificates } |
    Sort-Object Device, @{ Expression = { if ($null -eq $_.DaysToExpiry) { [int]::MaxValue } else { $_.DaysToExpiry } } }, Name)
$multiDevice = $okDevices.Count -gt 1

# Flat virtual server -> pool -> member rows.
$vsMemberRows = @(foreach ($v in $vsAll) {
    $members = @($v.MemberList)
    if ($members.Count -gt 0) {
        foreach ($m in $members) {
            [pscustomobject]@{
                Device = $v.Device; VirtualServer = $v.Name; Destination = $v.Address; Port = $v.Port; VirtualServerStatus = $v.Status
                Pool = $v.Pool; MemberName = $m.Name; MemberAddress = $m.Address; MemberPort = $m.Port; MemberStatus = $m.Status; Session = $m.Session
            }
        }
    } else {
        [pscustomobject]@{
            Device = $v.Device; VirtualServer = $v.Name; Destination = $v.Address; Port = $v.Port; VirtualServerStatus = $v.Status
            Pool = $v.Pool; MemberName = ''; MemberAddress = ''; MemberPort = ''; MemberStatus = ''; Session = ''
        }
    }
})

# Orphans: not associated with any virtual server, soonest expiry first.
$orphanRows = @($certAll |
    Where-Object { $_.Association -eq 'Orphaned' -and ($IncludeSystemCerts -or -not $_.IsSystemDefault) } |
    Sort-Object @{ Expression = { if ($null -eq $_.DaysToExpiry) { [int]::MaxValue } else { $_.DaysToExpiry } } }, Device, Name)

$countedCerts = @($certAll | Where-Object { $IncludeSystemCerts -or -not $_.IsSystemDefault })
$associatedCerts = @($countedCerts | Where-Object { $_.Association -eq 'Associated' })
$orphanExpiring = @($orphanRows | Where-Object { $_.ExpiresWithinThreshold -eq 'Yes' })
$orphanExpired = @($orphanRows | Where-Object { $null -ne $_.DaysToExpiry -and $_.DaysToExpiry -lt 0 })
$assocExpiring = @($associatedCerts | Where-Object { $_.ExpiresWithinThreshold -eq 'Yes' })
$memberTotal = ($poolAll | Measure-Object -Property MemberCount -Sum).Sum
if (-not $memberTotal) { $memberTotal = 0 }

# ---- File names ------------------------------------------------------------------
$f = @{
    Html    = Join-Path $OutputDirectory 'F5-Dashboard.html'
    Vs      = Join-Path $OutputDirectory 'F5-VirtualServers.csv'
    Members = Join-Path $OutputDirectory 'F5-VS-Pool-Members.csv'
    Pools   = Join-Path $OutputDirectory 'F5-Pools.csv'
    Certs   = Join-Path $OutputDirectory 'F5-Certificates.csv'
    Orphans = Join-Path $OutputDirectory 'F5-Orphaned-Certificates.csv'
    Json    = Join-Path $OutputDirectory 'F5-Inventory.json'
    Zip     = Join-Path $OutputDirectory 'F5-Report.zip'
}
$csvEncoding = if ($script:IsCore) { 'utf8BOM' } else { 'UTF8' }

# ---- CSV + JSON ------------------------------------------------------------------
$vsAll | Select-Object -Property * -ExcludeProperty MemberList, Bindings | Export-Csv -LiteralPath $f.Vs -NoTypeInformation -Encoding $csvEncoding
$vsMemberRows | Export-Csv -LiteralPath $f.Members -NoTypeInformation -Encoding $csvEncoding
$poolAll | Select-Object -Property * -ExcludeProperty MemberList | Export-Csv -LiteralPath $f.Pools -NoTypeInformation -Encoding $csvEncoding
$certAll | Export-Csv -LiteralPath $f.Certs -NoTypeInformation -Encoding $csvEncoding
if ($orphanRows.Count -gt 0) {
    $orphanRows | Select-Object Device, Name, CommonName, IssuerCN, ExpirationUtc, DaysToExpiry, ExpiryStatus, ExpiresWithinThreshold, OrphanReason, IsSystemDefault, SubjectAltNames, Subject, Issuer, Key, FullPath |
        Export-Csv -LiteralPath $f.Orphans -NoTypeInformation -Encoding $csvEncoding
} else {
    Set-Content -LiteralPath $f.Orphans -Value 'Device,Name,CommonName,IssuerCN,ExpirationUtc,DaysToExpiry,ExpiryStatus,ExpiresWithinThreshold,OrphanReason' -Encoding UTF8
}
$utf8Bom = New-Object System.Text.UTF8Encoding($true)
$inventory = [pscustomobject]@{
    GeneratedUtc      = $nowUtc.ToString('o', $inv)
    Devices           = $okDevices
    ExpiryWarningDays = $ExpiryWarningDays
    VirtualServers    = $vsAll
    Pools             = $poolAll
    Certificates      = $certAll
}
[System.IO.File]::WriteAllText($f.Json, ($inventory | ConvertTo-Json -Depth 6), $utf8Bom)

# ---- Dashboard -------------------------------------------------------------------
$deviceCol = @{ Header = 'Device'; Prop = 'Device'; Html = { param($r) "<code>$(Esc $r.Device)</code>" } }
function Add-DeviceColumn {
    param($Columns)
    if ($multiDevice) { return (@($deviceCol) + @($Columns)) }
    return @($Columns)
}

$vsCols = Add-DeviceColumn @(
    @{ Header = 'Virtual server'; Prop = 'Name'; Html = { param($r) "<code>$(Esc $r.Name)</code>" } }
    @{ Header = 'Destination'
       Plain  = { param($r) "$($r.Address):$($r.Port)" }
       Html   = { param($r) $d = "$($r.Address):$($r.Port)"; "<code>$(Esc $d)</code>" } }
    @{ Header = 'Protocol'; Prop = 'Protocol' }
    @{ Header = 'Status'; Prop = 'Status'
       Html   = { param($r) if ($r.Status -eq 'Disabled') { "<span class='badge s-soon'>Disabled</span>" } else { 'Enabled' } } }
    @{ Header = 'Pool'; Prop = 'Pool'
       Html   = { param($r) if ($r.Pool) { "<code>$(Esc $r.Pool)</code>" } else { "<span class='muted'>none</span>" } } }
    @{ Header = 'Pool members'
       Plain  = { param($r) $n = @($r.MemberList).Count; if ($n -eq 0) { '0 members' } else { "$n members: $($r.PoolMembers)" } }
       Html   = {
           param($r)
           $n = @($r.MemberList).Count
           if ($n -eq 0) { return "<span class='muted'>none</span>" }
           $notUp = @($r.MemberList | Where-Object { $_.Status -ne 'Up' }).Count
           $sum = "$n $(Get-Plural $n 'member')"
           if ($notUp -gt 0) { $sum += ", $notUp not up" }
           return "<details><summary>$sum</summary>$(New-MemberListHtml $r.MemberList)</details>"
       } }
    @{ Header = 'Certificates'
       Plain  = {
           param($r)
           Join-Text (@($r.Bindings | Sort-Object Certificate, Role -Unique) | ForEach-Object {
               $t = "$($_.Certificate) (expires $($_.ExpirationUtc), $($_.DaysToExpiry) days)"; $t })
       }
       Html   = {
           param($r)
           $items = @($r.Bindings | Sort-Object Certificate, Role -Unique)
           if ($items.Count -eq 0) { return "<span class='muted'>none</span>" }
           $out = foreach ($b in $items) {
               $lbl = Get-BindingLabel $b
               $lblHtml = if ($lbl) { " <span class='role'>($(Esc $lbl))</span>" } else { '' }
               "<div class='certline'><code>$(Esc $b.Certificate)</code>$lblHtml $(Get-DaysBadgeHtml $b.DaysToExpiry $b.ExpiryStatus)</div>"
           }
           return ($out -join '')
       } }
    @{ Header = 'iRules'; Prop = 'IRules'
       Html   = { param($r) if ($r.IRules) { "<code>$(Esc $r.IRules)</code>" } else { '' } } }
)

$poolCols = Add-DeviceColumn @(
    @{ Header = 'Pool'; Prop = 'Name'; Html = { param($r) "<code>$(Esc $r.Name)</code>" } }
    @{ Header = 'Load balancing'; Prop = 'LoadBalancing' }
    @{ Header = 'Monitor'; Prop = 'Monitor' }
    @{ Header = 'Members'
       Plain  = { param($r) if ($r.MemberCount -eq 0) { '0 members' } else { "$($r.MemberCount) members: $($r.Members)" } }
       Html   = {
           param($r)
           if ($r.MemberCount -eq 0) { return "<span class='muted'>none</span>" }
           $notUp = $r.MemberCount - $r.MembersUp
           $sum = "$($r.MemberCount) $(Get-Plural $r.MemberCount 'member')"
           if ($notUp -gt 0) { $sum += ", $notUp not up" }
           return "<details><summary>$sum</summary>$(New-MemberListHtml $r.MemberList)</details>"
       } }
    @{ Header = 'Default pool for'; Prop = 'UsedBy'
       Html   = { param($r) if ($r.UsedBy) { "<code>$(Esc $r.UsedBy)</code>" } else { "<span class='muted'>no virtual server</span>" } } }
)

$assocHtml = {
    param($r)
    if ($r.Association -eq 'Associated') { return "<span class='badge u-use'>Associated</span>" }
    return "<span class='badge u-orphan'>Orphaned</span>"
}
$daysCol = @{ Header = 'Days left'
    Plain = { param($r) if ($null -eq $r.DaysToExpiry) { '' } else { [string]$r.DaysToExpiry } }
    Html  = { param($r) Get-DaysBadgeHtml $r.DaysToExpiry $r.ExpiryStatus } }

$certCols = Add-DeviceColumn @(
    @{ Header = 'Certificate'; Prop = 'Name'
       Html   = { param($r) $sys = if ($r.IsSystemDefault) { " <span class='muted'>(F5 default)</span>" } else { '' }; "<code>$(Esc $r.Name)</code>$sys" } }
    @{ Header = 'Common name'; Prop = 'CommonName' }
    @{ Header = 'Issuer'; Prop = 'IssuerCN' }
    @{ Header = 'Expires (UTC)'; Prop = 'ExpirationUtc' }
    $daysCol
    @{ Header = 'Association'; Prop = 'Association'; Html = $assocHtml }
    @{ Header = 'Virtual servers'; Prop = 'VirtualServers'
       Html   = { param($r) if ($r.VirtualServers) { "<code>$(Esc $r.VirtualServers)</code>" } else { '' } } }
    @{ Header = 'Key'; Prop = 'Key' }
)

$orphanCols = Add-DeviceColumn @(
    @{ Header = 'Certificate'; Prop = 'Name'
       Html   = { param($r) $sys = if ($r.IsSystemDefault) { " <span class='muted'>(F5 default)</span>" } else { '' }; "<code>$(Esc $r.Name)</code>$sys" } }
    @{ Header = 'Common name'; Prop = 'CommonName' }
    @{ Header = 'Issuer'; Prop = 'IssuerCN' }
    @{ Header = 'Expires (UTC)'; Prop = 'ExpirationUtc' }
    $daysCol
    @{ Header = "Under $ExpiryWarningDays days"; Prop = 'ExpiresWithinThreshold'
       Html   = { param($r) if ($r.ExpiresWithinThreshold -eq 'Yes') { "<span class='badge s-crit'>Yes</span>" } else { 'No' } } }
    @{ Header = 'Why it is orphaned'; Prop = 'OrphanReason' }
)

$tblVs = New-TableHtml -Id 'vs' -Rows $vsAll -Columns $vsCols -Empty 'No virtual servers were returned.'
$tblPools = New-TableHtml -Id 'pools' -Rows $poolAll -Columns $poolCols -Empty 'No pools were returned.'
$tblCerts = New-TableHtml -Id 'certs' -Rows $certAll -Columns $certCols -Empty 'No certificates were returned.'
$tblOrphans = New-TableHtml -Id 'orphans' -Rows $orphanRows -Columns $orphanCols -Empty 'No orphaned certificates found.'

$sysNote = if ($IncludeSystemCerts) { 'F5 default certificates are included in these counts.' } else { 'F5 default certificates (for example default.crt and ca-bundle.crt) are marked and left out of the orphan counts.' }
$sections = @(
    (New-SectionHtml -Id 'virtual-servers' -Slug 'virtual-servers' -Heading 'Virtual servers' -Count $vsAll.Count `
        -NoteHtml 'Default pool, pool members and the certificates reached through each virtual server&#39;s client-SSL and server-SSL profiles. Member status is what the BIG-IP reported at collection time. A pool picked by an iRule or LTM policy instead of the default pool is not traced.' `
        -TableHtml $tblVs)
    (New-SectionHtml -Id 'pools' -Slug 'pools-and-members' -Heading 'Pools and members' -Count $poolAll.Count `
        -NoteHtml 'Every pool with its members. A pool that is not the default pool of any virtual server is shown as having no virtual server; it may still be selected by an iRule or policy.' `
        -TableHtml $tblPools)
    (New-SectionHtml -Id 'certificates' -Slug 'certificates' -Heading 'Certificates in the store' -Count $certAll.Count `
        -NoteHtml "Associated means the certificate, its chain or its CA file is referenced by an SSL profile attached to at least one virtual server. $(Esc $sysNote)" `
        -TableHtml $tblCerts)
    (New-SectionHtml -Id 'orphaned' -Slug 'orphaned-certificates' -Heading 'Orphaned certificates' -Count $orphanRows.Count `
        -NoteHtml "Certificates no virtual server uses, soonest expiry first. Certificates that expire in under $ExpiryWarningDays days, including those already expired, are marked Yes. Certificates used only by other features (HTTPS monitors, APM or SAML, device certificates) are not detected, so confirm before deleting anything." `
        -TableHtml $tblOrphans)
) -join "`n"

# Runway buckets.
$buckets = @(
    @{ Label = 'Expired';          Min = [int]::MinValue; Max = 0;             Class = 's-expired' }
    @{ Label = 'Under 30 days';    Min = 0;               Max = 30;            Class = 's-crit' }
    @{ Label = '30 to 59 days';    Min = 30;              Max = 60;            Class = 's-soon' }
    @{ Label = '60 to 89 days';    Min = 60;              Max = 90;            Class = 's-soon' }
    @{ Label = '90 to 179 days';   Min = 90;              Max = 180;           Class = 's-ok' }
    @{ Label = '180 days or more'; Min = 180;             Max = [int]::MaxValue; Class = 's-ok' }
)
$dated = @($countedCerts | Where-Object { $null -ne $_.DaysToExpiry })
foreach ($b in $buckets) {
    $inB = @($dated | Where-Object { $_.DaysToExpiry -ge $b.Min -and $_.DaysToExpiry -lt $b.Max })
    $b.Assoc = @($inB | Where-Object { $_.Association -eq 'Associated' }).Count
    $b.Orph = @($inB | Where-Object { $_.Association -eq 'Orphaned' }).Count
}
$maxBucket = ($buckets | ForEach-Object { $_.Assoc + $_.Orph } | Measure-Object -Maximum).Maximum
if (-not $maxBucket) { $maxBucket = 1 }
$runway = foreach ($b in $buckets) {
    $wA = Format-Pct (100.0 * $b.Assoc / $maxBucket)
    $wO = Format-Pct (100.0 * $b.Orph / $maxBucket)
    "<div class='rw-row $($b.Class)'><span class='rw-label'>$(Esc $b.Label)</span><span class='rw-bar' role='img' aria-label='$($b.Assoc) associated, $($b.Orph) orphaned'><i class='use' style='width:$wA%'></i><i class='orph' style='width:$wO%'></i></span><span class='rw-n'><b>$($b.Assoc + $b.Orph)</b> &nbsp;$($b.Assoc) associated, $($b.Orph) orphaned</span></div>"
}
$undated = $countedCerts.Count - $dated.Count
$runwayNote = if ($undated -gt 0) { "$undated $(Get-Plural $undated 'certificate') with no readable expiry date are not shown." } else { '' }

# Headline.
if ($orphanExpiring.Count -gt 0) {
    $verb = if ($orphanExpiring.Count -eq 1) { 'expires' } else { 'expire' }
    $headline = "$($orphanExpiring.Count) orphaned $(Get-Plural $orphanExpiring.Count 'certificate') $verb in under $ExpiryWarningDays days"
    if ($orphanExpired.Count -gt 0) { $headline += ", $($orphanExpired.Count) already expired" }
    $headline += '.'
} else {
    $headline = "No orphaned certificates expire in the next $ExpiryWarningDays days."
}
if ($assocExpiring.Count -gt 0) {
    $subline = "$($assocExpiring.Count) $(Get-Plural $assocExpiring.Count 'certificate') bound to virtual servers also $(if ($assocExpiring.Count -eq 1) { 'expires' } else { 'expire' }) inside that window."
} else {
    $subline = "No certificate bound to a virtual server expires inside that window."
}

$hotClass = if ($orphanExpiring.Count -gt 0) { 'hot' } else { '' }
$figureRows = @(
    [pscustomobject]@{ Label = 'Virtual servers';                           Value = $vsAll.Count;            Class = '' }
    [pscustomobject]@{ Label = 'Pools';                                     Value = $poolAll.Count;          Class = '' }
    [pscustomobject]@{ Label = 'Pool members';                              Value = $memberTotal;            Class = '' }
    [pscustomobject]@{ Label = 'Certificates in the store';                 Value = $certAll.Count;          Class = '' }
    [pscustomobject]@{ Label = 'Associated with a virtual server';          Value = $associatedCerts.Count;  Class = '' }
    [pscustomobject]@{ Label = 'Orphaned';                                  Value = $orphanRows.Count;       Class = '' }
    [pscustomobject]@{ Label = "Orphaned and under $ExpiryWarningDays days"; Value = $orphanExpiring.Count;   Class = $hotClass }
)
$figures = ($figureRows | ForEach-Object { "<div class='$($_.Class)'><dt>$(Esc $_.Label)</dt><dd>$($_.Value)</dd></div>" }) -join "`n"

$generated = $nowUtc.ToString('yyyy-MM-dd HH:mm', $inv)
$deviceHtml = ($okDevices | ForEach-Object { "<code>$(Esc $_)</code>" }) -join ', '
$meta = "Collected $generated UTC from $deviceHtml. Expiry window: $ExpiryWarningDays days."
$warn = ''
if ($failures.Count -gt 0) {
    $warn = "<p class='warn'><strong>Not collected:</strong> " + (($failures | ForEach-Object { "<code>$(Esc $_.Device)</code> ($(Esc $_.Reason))" }) -join '; ') + '</p>'
}

$downloads = "Download the full data: <a href='F5-Report.zip' download>ZIP bundle</a>, <a href='F5-Orphaned-Certificates.csv' download>orphaned certificates</a>, <a href='F5-Certificates.csv' download>all certificates</a>, <a href='F5-VirtualServers.csv' download>virtual servers</a>, <a href='F5-VS-Pool-Members.csv' download>virtual server and pool member rows</a>, <a href='F5-Pools.csv' download>pools</a>."
$nav = "<a href='#virtual-servers'>Virtual servers ($($vsAll.Count))</a><a href='#pools'>Pools and members ($($poolAll.Count))</a><a href='#certificates'>Certificates ($($certAll.Count))</a><a href='#orphaned'>Orphaned certificates ($($orphanRows.Count))</a>"
$footer = "<p>Orphaned means no SSL profile attached to a virtual server references the certificate, its chain or its CA file. Days left are counted from collection time. Data comes from the iControl REST endpoints /mgmt/tm/ltm/virtual, /ltm/pool, /ltm/profile/client-ssl, /ltm/profile/server-ssl and /sys/file/ssl-cert.</p>"

$page = $HtmlTemplate.
    Replace('%%TITLE%%', (Esc $Title)).
    Replace('%%META%%', $meta).
    Replace('%%WARN%%', $warn).
    Replace('%%HEADLINE%%', (Esc $headline)).
    Replace('%%SUBLINE%%', (Esc $subline)).
    Replace('%%RUNWAYNOTE%%', (Esc $runwayNote)).
    Replace('%%RUNWAY%%', ($runway -join "`n")).
    Replace('%%FIGURES%%', $figures).
    Replace('%%DOWNLOADS%%', $downloads).
    Replace('%%NAV%%', $nav).
    Replace('%%SECTIONS%%', $sections).
    Replace('%%FOOTER%%', $footer)
[System.IO.File]::WriteAllText($f.Html, $page, $utf8Bom)

# ---- Zip + publish ---------------------------------------------------------------
$bundle = @($f.Html, $f.Vs, $f.Members, $f.Pools, $f.Certs, $f.Orphans, $f.Json)
Compress-Archive -LiteralPath $bundle -DestinationPath $f.Zip -Force
Copy-Item -LiteralPath $f.Zip -Destination (Join-Path $archiveDir "F5-Report_$stamp.zip") -Force

if ($PublishPath) {
    if (-not (Test-Path -LiteralPath $PublishPath)) { New-Item -ItemType Directory -Path $PublishPath -Force | Out-Null }
    Copy-Item -LiteralPath ($bundle + $f.Zip) -Destination $PublishPath -Force
    Write-Host "Published to $PublishPath"
}

Write-Host ''
Write-Host "Virtual servers: $($vsAll.Count)   Pools: $($poolAll.Count)   Pool members: $memberTotal   Certificates: $($certAll.Count)"
Write-Host "Associated: $($associatedCerts.Count)   Orphaned: $($orphanRows.Count)   Orphaned and under ${ExpiryWarningDays} days: $($orphanExpiring.Count)"
Write-Host "Dashboard: $($f.Html)"
Write-Host "Reports:   $OutputDirectory"
