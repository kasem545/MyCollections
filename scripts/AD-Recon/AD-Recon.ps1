<#
.SYNOPSIS
    Pure LDAP Active Directory Reconnaissance (no AD module).
.DESCRIPTION
    Read-only LDAP queries via System.DirectoryServices.Protocols.
    Correctly classifies Kerberos encryption types:
      - unset / 0x00  -> inherit (not a finding)
      - 0x1C          -> modern default AES+RC4 (not a finding)
      - 0x18          -> AES-only (best practice)
      - 0x04          -> RC4-only (weak)
      - any DES bit   -> broken
.NOTES
    ASCII-only. Safe to save as UTF-8 without BOM in Windows PowerShell 5.1.
#>

Add-Type -AssemblyName System.DirectoryServices
Add-Type -AssemblyName System.DirectoryServices.Protocols

# =====================================================================
#  Presentation helpers
# =====================================================================
function Write-Banner {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 72) -ForegroundColor DarkCyan
    Write-Host ("  " + $Text) -ForegroundColor Cyan
    Write-Host ("=" * 72) -ForegroundColor DarkCyan
}

function Write-Row {
    param(
        [string]$Label,
        $Value,
        [int]$LabelWidth = 30,
        [string]$Note = "",
        [ConsoleColor]$ValueColor = [ConsoleColor]::White
    )
    Write-Host ("  {0,-$LabelWidth} : " -f $Label) -NoNewline
    Write-Host $Value -ForegroundColor $ValueColor -NoNewline
    if ($Note) { Write-Host "  $Note" -ForegroundColor DarkGray } else { Write-Host "" }
}

function Write-Finding {
    param(
        [ValidateSet("INFO","LOW","MEDIUM","HIGH")][string]$Severity,
        [string]$Message
    )
    $color = switch ($Severity) {
        "INFO"   { "Gray" }
        "LOW"    { "Green" }
        "MEDIUM" { "Yellow" }
        "HIGH"   { "Red" }
    }
    Write-Host ("  [{0,-6}] " -f $Severity) -ForegroundColor $color -NoNewline
    Write-Host $Message
}

# =====================================================================
#  LDAP helpers
# =====================================================================
function Get-DcHostName {
    param([string]$Server)
    if ($Server) { return $Server }
    try {
        $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        if ($d.DomainControllers.Count -gt 0) { return $d.DomainControllers[0].Name }
    } catch { }
    if ($env:USERDNSDOMAIN) { return $env:USERDNSDOMAIN }
    if ($env:USERDOMAIN)     { return $env:USERDOMAIN }
    throw "Could not determine a domain/DC. Pass -Server explicitly."
}

function Get-LdapConnection {
    param(
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )
    $dc = Get-DcHostName -Server $Server
    $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($dc, 389, $false, $false)
    $conn = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier)
    $conn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
    $conn.SessionOptions.ReferralChasing = [System.DirectoryServices.Protocols.ReferralChasingOptions]::None
    $conn.Timeout = [TimeSpan]::FromSeconds(20)
    if ($Credential) { $conn.Bind($Credential.GetNetworkCredential()) } else { $conn.Bind() }
    return $conn
}

function Get-DomainDN {
    param($Connection)
    $r = New-Object System.DirectoryServices.Protocols.SearchRequest(
        $null, "(objectClass=*)",
        [System.DirectoryServices.Protocols.SearchScope]::Base,
        [string[]]@("defaultNamingContext"))
    $resp = $Connection.SendRequest($r)
    if ($resp.Entries.Count -eq 0) { throw "Root DSE returned no entries." }
    return $resp.Entries[0].Attributes["defaultNamingContext"][0]
}

function Get-Attr {
    param($Entry, [string]$Name)
    if ($null -eq $Entry -or $null -eq $Entry.Attributes) { return $null }
    if (-not $Entry.Attributes.Contains($Name)) { return $null }
    $attr = $Entry.Attributes[$Name]
    if ($null -eq $attr -or $attr.Count -eq 0) { return $null }
    return $attr[0]
}

# =====================================================================
#  Interpretation helpers
# =====================================================================
function Convert-TicksToDuration {
    param($Ticks)
    $t = [int64]$Ticks
    if ($t -eq 0 -or $t -eq [int64]::MinValue) { return "never" }
    $abs = [math]::Abs($t)
    $ts  = [TimeSpan]::FromTicks($abs)
    if ($ts.TotalDays -ge 1)    { return ("{0:N2} days" -f $ts.TotalDays) }
    if ($ts.TotalHours -ge 1)   { return ("{0:N2} hours" -f $ts.TotalHours) }
    if ($ts.TotalMinutes -ge 1) { return ("{0:N2} minutes" -f $ts.TotalMinutes) }
    return ("{0:N0} seconds" -f $ts.TotalSeconds)
}

# --- Encryption classification -------------------------------------
# Profiles:
#   INHERIT   - unset or 0x00; DC default applies        (no finding)
#   AES-ONLY  - 0x18 or any AES-only mask               (best)
#   AES-RC4   - AES present + RC4 present (0x1C etc.)   (modern default, no finding)
#   AES128    - AES128 only, no AES256                  (low)
#   RC4       - RC4 only, no AES, no DES                (medium)
#   DES       - any DES bit set                         (high)
#   UNKNOWN   - anything else
function Get-EncryptionDescription {
    param($Value)

    # Unset attribute -> inherit
    if ($null -eq $Value) {
        return @{
            Text     = "inherit (domain default)"
            Profile  = "INHERIT"
            AES      = $true
            AES128   = $true
            AES256   = $true
            RC4      = $true
            DES      = $false
            Explicit = $false
        }
    }

    $v = [int]$Value

    # Explicit zero -> treat as inherit (DC will use its own default)
    if ($v -eq 0) {
        return @{
            Text     = "0x00 (cleared - inherit default)"
            Profile  = "INHERIT"
            AES      = $true
            AES128   = $true
            AES256   = $true
            RC4      = $true
            DES      = $false
            Explicit = $true
        }
    }

    $desCrc  = ($v -band 0x1)  -ne 0
    $desMd5  = ($v -band 0x2)  -ne 0
    $rc4     = ($v -band 0x4)  -ne 0
    $aes128  = ($v -band 0x8)  -ne 0
    $aes256  = ($v -band 0x10) -ne 0

    $aes = $aes128 -or $aes256
    $des = $desCrc -or $desMd5

    # Classify
    if ($des)                              { $profile = "DES" }
    elseif ($aes256 -and $aes128 -and $rc4) { $profile = "AES-RC4" }   # 0x1C, modern default
    elseif ($aes256 -and -not $rc4)         { $profile = "AES-ONLY" }  # 0x18, best
    elseif ($aes128 -and -not $aes256)      { $profile = "AES128" }
    elseif ($rc4 -and -not $aes)            { $profile = "RC4" }
    elseif ($aes)                           { $profile = "AES-ONLY" }
    else                                    { $profile = "UNKNOWN" }

    $names = @()
    if ($aes256) { $names += "AES256" }
    if ($aes128) { $names += "AES128" }
    if ($rc4)    { $names += "RC4-HMAC" }
    if ($desMd5) { $names += "DES-MD5" }
    if ($desCrc) { $names += "DES-CRC" }
    if ($names.Count -eq 0) { $names += "(none)" }

    return @{
        Text     = ("{0}  [0x{1:X2}]" -f ($names -join "+"), $v)
        Profile  = $profile
        AES      = $aes
        AES128   = $aes128
        AES256   = $aes256
        RC4      = $rc4
        DES      = $des
        Explicit = $true
    }
}

# =====================================================================
#  MAIN
# =====================================================================
$findingCounts = @{ HIGH = 0; MEDIUM = 0; LOW = 0; INFO = 0 }

try {
    $conn = Get-LdapConnection
} catch {
    Write-Host "Failed to bind to LDAP: $_" -ForegroundColor Red
    return
}

$domainDN = Get-DomainDN -Connection $conn

Write-Banner "Active Directory Reconnaissance Report"
Write-Row "LDAP server" (Get-DcHostName)
Write-Row "Domain DN"   $domainDN
Write-Row "Timestamp"   (Get-Date -Format "u")

# ---------------------------------------------------------------------
#  1. Domain Controllers
# ---------------------------------------------------------------------
Write-Banner "1. Domain Controllers"

$dcEntries = @()
try {
    $filter = "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
    $r = New-Object System.DirectoryServices.Protocols.SearchRequest(
        $domainDN, $filter,
        [System.DirectoryServices.Protocols.SearchScope]::Subtree,
        [string[]]@("name","msDS-isRODC","operatingSystem","dNSHostName","operatingSystemVersion"))
    $resp = $conn.SendRequest($r)
    foreach ($e in $resp.Entries) {
        $dcEntries += [PSCustomObject]@{
            Name   = Get-Attr $e "name"
            IsRODC = (Get-Attr $e "msDS-isRODC") -eq "TRUE"
            OS     = Get-Attr $e "operatingSystem"
            OSVer  = Get-Attr $e "operatingSystemVersion"
            DNS    = Get-Attr $e "dNSHostName"
        }
    }
} catch { Write-Host "  query failed: $_" -ForegroundColor Red }

if ($dcEntries.Count -eq 0) {
    Write-Host "  (no DC entries returned)" -ForegroundColor DarkGray
} else {
    Write-Host ("  {0,-28} {1,-8} {2}" -f "NAME", "RODC", "OPERATING SYSTEM") -ForegroundColor DarkGray
    Write-Host ("  " + ("-" * 68)) -ForegroundColor DarkGray
    foreach ($dc in $dcEntries) {
        $rodcColor = if ($dc.IsRODC) { "Yellow" } else { "Gray" }
        $rodcText  = if ($dc.IsRODC) { "yes" }    else { "no" }
        Write-Host ("  {0,-28} " -f $dc.Name) -NoNewline
        Write-Host ("{0,-8} " -f $rodcText) -ForegroundColor $rodcColor -NoNewline
        Write-Host $dc.OS
    }
    $rodcCount = @($dcEntries | Where-Object IsRODC).Count
    if ($rodcCount -gt 0) {
        Write-Host ""
        Write-Finding MEDIUM "Read-Only DC(s) present ($rodcCount). Often deployed at less-secure branch sites."
        $findingCounts.MEDIUM++
    }
    Write-Finding INFO "$($dcEntries.Count) writable/read-only DC(s) enumerated."
    $findingCounts.INFO++
}

# ---------------------------------------------------------------------
#  2. Password & Lockout Policy
# ---------------------------------------------------------------------
Write-Banner "2. Default Domain Password & Lockout Policy"

$policy = $null
try {
    $attrs = @("minPwdLength","pwdHistoryLength","pwdProperties","maxPwdAge",
               "minPwdAge","lockoutThreshold","lockoutDuration","lockoutObservationWindow")
    $r = New-Object System.DirectoryServices.Protocols.SearchRequest(
        $domainDN, "(objectClass=domainDNS)",
        [System.DirectoryServices.Protocols.SearchScope]::Base,
        [string[]]$attrs)
    $resp = $conn.SendRequest($r)
    if ($resp.Entries.Count -gt 0) {
        $e = $resp.Entries[0]
        $policy = @{
            MinPwdLength       = Get-Attr $e "minPwdLength"
            PwdHistoryLength   = Get-Attr $e "pwdHistoryLength"
            PwdProperties      = Get-Attr $e "pwdProperties"
            MaxPwdAge          = Get-Attr $e "maxPwdAge"
            MinPwdAge          = Get-Attr $e "minPwdAge"
            LockoutThreshold   = Get-Attr $e "lockoutThreshold"
            LockoutDuration    = Get-Attr $e "lockoutDuration"
            LockoutObservation = Get-Attr $e "lockoutObservationWindow"
        }
    }
} catch { Write-Host "  query failed: $_" -ForegroundColor Red }

if (-not $policy) {
    Write-Host "  (no policy returned)" -ForegroundColor DarkGray
} else {
    $minLen  = [int]$policy.MinPwdLength
    $hist    = [int]$policy.PwdHistoryLength
    $props   = [int]$policy.PwdProperties
    $lockout = [int]$policy.LockoutThreshold

    $complexityEnabled = ($props -band 0x1)  -ne 0
    $storeCleartext    = ($props -band 0x10) -ne 0

    $lenNote  = ""
    $lenColor = "Green"
    if ($minLen -lt 8)       { $lenNote = "(< 8 - weak)";                  $lenColor = "Red" }
    elseif ($minLen -lt 14)  { $lenNote = "(< 14 - below modern baseline)"; $lenColor = "Yellow" }

    Write-Host "  Password:" -ForegroundColor Cyan
    Write-Row "Minimum length"        $minLen -Note $lenNote -ValueColor $lenColor
    Write-Row "Password history"      $hist
    Write-Row "Complexity required"   $complexityEnabled -ValueColor $(if ($complexityEnabled) {"Green"} else {"Red"})
    Write-Row "Reversible encryption" $storeCleartext    -ValueColor $(if ($storeCleartext)    {"Red"}   else {"Green"})
    Write-Row "Max password age"      (Convert-TicksToDuration $policy.MaxPwdAge)
    Write-Row "Min password age"      (Convert-TicksToDuration $policy.MinPwdAge)

    Write-Host ""
    Write-Host "  Lockout:" -ForegroundColor Cyan
    $lockoutEnabled = $lockout -gt 0
    $lockoutText    = if ($lockoutEnabled) { "{0} attempts" -f $lockout } else { "0 (DISABLED)" }
    $lockoutColor   = if ($lockoutEnabled) { "Green" } else { "Red" }
    Write-Row "Lockout threshold"  $lockoutText -ValueColor $lockoutColor
    Write-Row "Lockout duration"   (Convert-TicksToDuration $policy.LockoutDuration)
    Write-Row "Observation window" (Convert-TicksToDuration $policy.LockoutObservation)

    Write-Host ""
    Write-Host "  Findings:" -ForegroundColor Cyan

    if ($minLen -lt 8) {
        Write-Finding HIGH "Minimum password length is $minLen (should be >= 14 per modern guidance)."
        $findingCounts.HIGH++
    } elseif ($minLen -lt 14) {
        Write-Finding MEDIUM "Minimum password length is $minLen (below 14-char modern baseline)."
        $findingCounts.MEDIUM++
    } else {
        Write-Finding LOW "Minimum password length is $minLen (meets modern baseline)."
        $findingCounts.LOW++
    }

    if (-not $complexityEnabled) {
        Write-Finding HIGH "Password complexity is DISABLED."
        $findingCounts.HIGH++
    } else {
        Write-Finding LOW "Password complexity is enabled."
        $findingCounts.LOW++
    }

    if (-not $lockoutEnabled) {
        Write-Finding HIGH "Account lockout is DISABLED - unlimited brute-force attempts possible."
        $findingCounts.HIGH++
    } else {
        Write-Finding LOW ("Account lockout is enabled ({0} attempts)." -f $lockout)
        $findingCounts.LOW++
    }

    if ($storeCleartext) {
        Write-Finding HIGH "Reversible password encryption is ENABLED (cleartext-equivalent storage)."
        $findingCounts.HIGH++
    }
}

# ---------------------------------------------------------------------
#  3. Kerberos Encryption Types
# ---------------------------------------------------------------------
Write-Banner "3. Kerberos Supported Encryption Types"

Write-Host "  Legend: 0x18 = AES128+AES256 | 0x1C = AES+RC4 (modern default) |" -ForegroundColor DarkGray
Write-Host "          0x04 = RC4-HMAC | 0x01/0x02 = DES | unset/0x00 = inherit" -ForegroundColor DarkGray
Write-Host ""

function Get-EncryptionSample {
    param($Conn, $DomainDN, $ObjectCategory, $MaxResults = 15)

    # Aggregated buckets by profile
    $result = @{
        Total    = 0
        Entries  = @()
        ByProfile = @{
            "INHERIT"  = @()
            "AES-ONLY" = @()
            "AES-RC4"  = @()
            "AES128"   = @()
            "RC4"      = @()
            "DES"      = @()
            "UNKNOWN"  = @()
        }
    }

    try {
        $filter = "(objectCategory=$ObjectCategory)"
        $attrs  = [string[]]@("name","sAMAccountName","msDS-SupportedEncryptionTypes","userAccountControl")
        $r = New-Object System.DirectoryServices.Protocols.SearchRequest(
            $DomainDN, $filter,
            [System.DirectoryServices.Protocols.SearchScope]::Subtree, $attrs)
        $paged = New-Object System.DirectoryServices.Protocols.PageResultRequestControl($MaxResults)
        [void]$r.Controls.Add($paged)
        $resp = $Conn.SendRequest($r)

        foreach ($e in $resp.Entries) {
            $name = Get-Attr $e "name"
            $sam  = Get-Attr $e "sAMAccountName"
            $uac  = Get-Attr $e "userAccountControl"
            $enc  = Get-Attr $e "msDS-SupportedEncryptionTypes"
            $desc = Get-EncryptionDescription $enc

            $disabled = $false
            if ($null -ne $uac) { $disabled = ([int]$uac -band 0x2) -ne 0 }

            $obj = [PSCustomObject]@{
                Name     = $name
                SAM      = $sam
                Desc     = $desc
                Disabled = $disabled
            }
            $result.Entries += $obj
            $result.Total++

            if (-not $disabled) {
                $result.ByProfile[$desc.Profile] += $obj
            }
        }
    } catch {
        Write-Host "  $ObjectCategory query failed: $_" -ForegroundColor Red
    }
    return $result
}

function Show-EncryptionSample {
    param($Sample, [string]$Category)
    Write-Host "  -- $Category accounts (sample of $($Sample.Total)) --" -ForegroundColor Cyan
    if ($Sample.Total -eq 0) {
        Write-Host "     (none returned)" -ForegroundColor DarkGray
        return
    }
    Write-Host ("  {0,-24} {1,-22} {2,-12} {3}" -f "NAME", "SAM", "PROFILE", "ENCRYPTION TYPES") -ForegroundColor DarkGray
    Write-Host ("  " + ("-" * 88)) -ForegroundColor DarkGray

    foreach ($row in $Sample.Entries) {
        $color = switch ($row.Desc.Profile) {
            "DES"      { "Red" }
            "RC4"      { "Red" }
            "AES128"   { "Yellow" }
            "UNKNOWN"  { "Yellow" }
            "AES-RC4"  { "White" }    # modern default - normal
            "AES-ONLY" { "Green" }    # best
            "INHERIT"  { "Gray" }
            default    { "White" }
        }
        if ($row.Disabled) { $color = "DarkGray" }

        $note = ""
        if ($row.Disabled) { $note = " (disabled)" }

        Write-Host ("  {0,-24} {1,-22} " -f $row.Name, $row.SAM) -NoNewline -ForegroundColor $color
        Write-Host ("{0,-12} " -f $row.Desc.Profile) -NoNewline -ForegroundColor $color
        Write-Host ("{0,-34}" -f $row.Desc.Text) -NoNewline -ForegroundColor $color
        Write-Host $note -ForegroundColor DarkGray
    }
    Write-Host ""
}

$userSample = Get-EncryptionSample -Conn $conn -DomainDN $domainDN -ObjectCategory "user"
$compSample = Get-EncryptionSample -Conn $conn -DomainDN $domainDN -ObjectCategory "computer"

Show-EncryptionSample -Sample $userSample -Category "User"
Show-EncryptionSample -Sample $compSample -Category "Computer"

Write-Host "  Profile distribution (non-disabled accounts):" -ForegroundColor Cyan
foreach ($profile in @("AES-ONLY","AES-RC4","AES128","RC4","DES","INHERIT","UNKNOWN")) {
    $u = @($userSample.ByProfile[$profile]).Count
    $c = @($compSample.ByProfile[$profile]).Count
    if ($u -eq 0 -and $c -eq 0) { continue }
    Write-Host ("    {0,-10}  users: {1,-4}  computers: {2}" -f $profile, $u, $c)
}
Write-Host ""

Write-Host "  Findings:" -ForegroundColor Cyan

$desObjects     = @($userSample.ByProfile["DES"]     + $compSample.ByProfile["DES"])
$rc4Objects     = @($userSample.ByProfile["RC4"]     + $compSample.ByProfile["RC4"])
$aes128Objects  = @($userSample.ByProfile["AES128"]  + $compSample.ByProfile["AES128"])
$unknownObjects = @($userSample.ByProfile["UNKNOWN"] + $compSample.ByProfile["UNKNOWN"])

if ($desObjects.Count -gt 0) {
    Write-Finding HIGH "$($desObjects.Count) object(s) support DES - deprecated and broken. Remove DES from msDS-SupportedEncryptionTypes."
    $findingCounts.HIGH++
} else {
    Write-Finding LOW "No DES-supporting objects."
    $findingCounts.LOW++
}

if ($rc4Objects.Count -gt 0) {
    Write-Finding HIGH "$($rc4Objects.Count) object(s) are explicitly RC4-only - Kerberoasting target, no AES fallback."
    $findingCounts.HIGH++
} else {
    Write-Finding LOW "No RC4-only objects."
    $findingCounts.LOW++
}

if ($aes128Objects.Count -gt 0) {
    Write-Finding MEDIUM "$($aes128Objects.Count) object(s) support AES128 but not AES256 - consider enabling AES256."
    $findingCounts.MEDIUM++
}

if ($unknownObjects.Count -gt 0) {
    Write-Finding MEDIUM "$($unknownObjects.Count) object(s) have an unrecognised encryption mask."
    $findingCounts.MEDIUM++
}

# Informational: modern default and best-practice counts
$modernCount = @($userSample.ByProfile["AES-RC4"] + $compSample.ByProfile["AES-RC4"]).Count
$bestCount   = @($userSample.ByProfile["AES-ONLY"] + $compSample.ByProfile["AES-ONLY"]).Count
$inheritCount = @($userSample.ByProfile["INHERIT"] + $compSample.ByProfile["INHERIT"]).Count

if ($modernCount -gt 0) {
    Write-Finding INFO "$modernCount object(s) use the modern default AES256+AES128+RC4 (0x1C). No action required."
    $findingCounts.INFO++
}
if ($bestCount -gt 0) {
    Write-Finding INFO "$bestCount object(s) are AES-only (0x18). Best practice."
    $findingCounts.INFO++
}
if ($inheritCount -gt 0) {
    Write-Finding INFO "$inheritCount object(s) inherit encryption settings (unset or 0x00). DC default applies."
    $findingCounts.INFO++
}

# ---------------------------------------------------------------------
#  4. Summary
# ---------------------------------------------------------------------
Write-Banner "Summary"

Write-Host "  Findings by severity:"
Write-Host ("    HIGH    : {0}" -f $findingCounts.HIGH)   -ForegroundColor $(if ($findingCounts.HIGH)   {"Red"}    else {"DarkGray"})
Write-Host ("    MEDIUM  : {0}" -f $findingCounts.MEDIUM) -ForegroundColor $(if ($findingCounts.MEDIUM) {"Yellow"} else {"DarkGray"})
Write-Host ("    LOW     : {0}" -f $findingCounts.LOW)    -ForegroundColor $(if ($findingCounts.LOW)    {"Green"}  else {"DarkGray"})
Write-Host ""

if ($findingCounts.HIGH -gt 0) {
    Write-Host "  Overall: " -NoNewline
    Write-Host "WEAK CONFIGURATION - address HIGH findings first." -ForegroundColor Red
} elseif ($findingCounts.MEDIUM -gt 0) {
    Write-Host "  Overall: " -NoNewline
    Write-Host "MODERATE - some improvements recommended." -ForegroundColor Yellow
} else {
    Write-Host "  Overall: " -NoNewline
    Write-Host "OK - no significant issues detected in the sampled scope." -ForegroundColor Green
}

$conn.Dispose()
Write-Host ""