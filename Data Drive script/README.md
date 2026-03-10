<#
.SYNOPSIS
    Comprehensive Group Policy Object Documentation & Audit Tool

.DESCRIPTION
    Automatically documents every GPO in the Active Directory domain and generates
    a professional HTML report covering metadata, links, security filtering, WMI
    filters, delegation, configured settings, and potential issues.

.PARAMETER OutputPath
    Directory where the HTML report will be saved. Defaults to the current directory.

.PARAMETER ReportName
    Base file name for the report (without extension). Defaults to "GPO_Report_<timestamp>".

.PARAMETER DomainName
    FQDN of the target domain. Defaults to the current user's domain.

.PARAMETER IncludeSettingsDetail
    When specified, embeds the full Microsoft GPO HTML settings report for every GPO.
    This makes the report significantly larger but gives complete setting-level detail.

.PARAMETER StaleThresholdDays
    Number of days after which an unmodified GPO is flagged as stale. Default: 365.

.EXAMPLE
    .\Export-GPOReport.ps1
    Generates a report for the current domain in the current directory.

.EXAMPLE
    .\Export-GPOReport.ps1 -OutputPath "C:\Reports" -IncludeSettingsDetail -StaleThresholdDays 180
    Full-detail report with a 180-day staleness threshold saved to C:\Reports.

.NOTES
    Requirements:
      - Windows Server with RSAT: Group Policy Management Tools
      - ActiveDirectory PowerShell module
      - GroupPolicy PowerShell module
      - Sufficient read permissions on all GPOs
    Author : GPO Audit Script Generator
    Version: 4.0
#>

[CmdletBinding()]
param(
    [string]$OutputPath = (Get-Location).Path,
    [string]$ReportName = "",
    [string]$DomainName = "",
    [switch]$IncludeSettingsDetail,
    [int]$StaleThresholdDays = 365
)

# ─────────────────────────────────────────────────────────────────────────────
# Region: Initialization
# ─────────────────────────────────────────────────────────────────────────────
Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"
$ProgressPreference    = "Continue"

# FIX #4 & #6 — Global error tracking with structured log
$script:errorCount = 0
$script:errorLog   = [System.Collections.ArrayList]::new()

function Add-ScriptError {
    param([string]$GPOName, [string]$Phase, [string]$Message)
    $script:errorCount++
    [void]$script:errorLog.Add([PSCustomObject]@{
        GPO   = $GPOName
        Phase = $Phase
        Error = $Message
        Time  = Get-Date -Format 'HH:mm:ss'
    })
    Write-Warning "  [$Phase] $GPOName : $Message"
}

# Verify required modules
foreach ($mod in @('GroupPolicy', 'ActiveDirectory')) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Error "Required module '$mod' is not installed. Install RSAT tools and retry."
        exit 1
    }
    Import-Module $mod -ErrorAction Stop
}

if ([string]::IsNullOrWhiteSpace($DomainName)) {
    try {
        $DomainName = (Get-ADDomain -ErrorAction Stop).DNSRoot
    } catch {
        Write-Error "Cannot determine domain: $_"
        exit 1
    }
}

if ([string]::IsNullOrWhiteSpace($ReportName)) {
    $ReportName = "GPO_Report_{0}" -f (Get-Date -Format "yyyyMMdd_HHmmss")
}

$reportFile = Join-Path $OutputPath "$ReportName.html"
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

# FIX #3 — Removed unused $domainDN variable
$today     = Get-Date
$staleDate = $today.AddDays(-$StaleThresholdDays)

Write-Host "`n[*] GPO Documentation Tool v4.0" -ForegroundColor Cyan
Write-Host "[*] Domain  : $DomainName" -ForegroundColor Cyan
Write-Host "[*] Output  : $reportFile`n" -ForegroundColor Cyan

# ─────────────────────────────────────────────────────────────────────────────
# Region: Data Collection
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[1/6] Collecting GPO objects..." -ForegroundColor Yellow

try {
    $allGPOs = @(Get-GPO -All -Domain $DomainName -ErrorAction Stop | Sort-Object DisplayName)
} catch {
    Write-Error "FATAL: Cannot enumerate GPOs — $_"
    exit 1
}

$totalGPOs   = $allGPOs.Count
$gpoDataList = [System.Collections.ArrayList]::new()
$gpoXmlCache = @{}   # FIX #2 — Cache XML so conflict detection doesn't re-fetch

if ($totalGPOs -eq 0) {
    Write-Warning "No GPOs found in domain '$DomainName'."
    exit 0
}

Write-Host "[2/6] Gathering link, delegation, and filter data for $totalGPOs GPOs..." -ForegroundColor Yellow
$counter = 0

foreach ($gpo in $allGPOs) {
    $counter++
    $pct = [math]::Round(($counter / $totalGPOs) * 100)
    Write-Progress -Activity "Processing GPOs" -Status "$counter of $totalGPOs – $($gpo.DisplayName)" -PercentComplete $pct

    # FIX #1 & #7 — Reset per-iteration to prevent stale data from prior GPO
    $gpoXml = $null
    $ns     = $null

    # ── XML Report (fetched ONCE, cached for conflict detection) ─────
    try {
        [xml]$gpoXml = Get-GPOReport -Guid $gpo.Id -ReportType Xml -Domain $DomainName -ErrorAction Stop
        $ns = New-Object System.Xml.XmlNamespaceManager($gpoXml.NameTable)
        $ns.AddNamespace("gp", "http://www.microsoft.com/GroupPolicy/Settings")
        # FIX #2 — Store in cache for reuse during conflict detection
        $gpoXmlCache[$gpo.Id.ToString()] = $gpoXml
    } catch {
        Add-ScriptError $gpo.DisplayName "XMLReport" $_.Exception.Message
    }

    # ── Links ────────────────────────────────────────────────────────
    $links = [System.Collections.ArrayList]::new()
    if ($gpoXml -and $ns) {
        try {
            foreach ($linkNode in $gpoXml.SelectNodes("//gp:LinksTo", $ns)) {
                [void]$links.Add([PSCustomObject]@{
                    Path     = $linkNode.SOMPath
                    Enabled  = $linkNode.Enabled
                    Enforced = $linkNode.NoOverride
                })
            }
        } catch {
            Add-ScriptError $gpo.DisplayName "LinkParsing" $_.Exception.Message
        }
    }

    # ── Security Filtering + Delegation (single API call) ────────────
    $securityFilter = [System.Collections.ArrayList]::new()
    $delegation     = [System.Collections.ArrayList]::new()
    try {
        $perms = Get-GPPermission -Guid $gpo.Id -All -Domain $DomainName -ErrorAction Stop
        foreach ($perm in $perms) {
            if ($perm.Permission -eq 'GpoApply') {
                [void]$securityFilter.Add([PSCustomObject]@{
                    Trustee     = $perm.Trustee.Name
                    TrusteeType = $perm.Trustee.SidType.ToString()
                    Permission  = $perm.Permission.ToString()
                })
            }
            [void]$delegation.Add([PSCustomObject]@{
                Trustee     = $perm.Trustee.Name
                TrusteeType = $perm.Trustee.SidType.ToString()
                Permission  = $perm.Permission.ToString()
                Inherited   = $perm.Inherited
            })
        }
    } catch {
        Add-ScriptError $gpo.DisplayName "Permissions" $_.Exception.Message
    }

    # ── WMI Filter ───────────────────────────────────────────────────
    $wmiFilterName  = "None"
    $wmiFilterQuery = ""
    if ($gpo.WmiFilter) {
        $wmiFilterName  = $gpo.WmiFilter.Name
        $wmiFilterQuery = $gpo.WmiFilter.Query
    }

    # ── Settings detail (optional full HTML embed) ───────────────────
    $settingsHtml = ""
    if ($IncludeSettingsDetail) {
        try {
            $settingsHtml = Get-GPOReport -Guid $gpo.Id -ReportType Html -Domain $DomainName -ErrorAction Stop
            if ($settingsHtml -match '(?s)<body[^>]*>(.*)</body>') {
                $settingsHtml = $Matches[1]
            }
        } catch {
            $settingsHtml = "<p class='warning'>Unable to retrieve settings detail.</p>"
            Add-ScriptError $gpo.DisplayName "SettingsHTML" $_.Exception.Message
        }
    }

    # ── Detect whether settings are configured ───────────────────────
    # FIX #1 — Only runs when $gpoXml was actually set for THIS iteration
    $computerConfigured = $false
    $userConfigured     = $false
    if ($gpoXml -and $ns) {
        try {
            $compExt = $gpoXml.SelectNodes("//gp:Computer/gp:ExtensionData", $ns)
            $userExt = $gpoXml.SelectNodes("//gp:User/gp:ExtensionData", $ns)
            if ($compExt -and $compExt.Count -gt 0) { $computerConfigured = $true }
            if ($userExt -and $userExt.Count -gt 0) { $userConfigured = $true }
        } catch {
            Add-ScriptError $gpo.DisplayName "SettingsDetection" $_.Exception.Message
        }
    }

    $gpoStatus = switch ($gpo.GpoStatus) {
        'AllSettingsEnabled'       { 'All Settings Enabled' }
        'UserSettingsDisabled'     { 'User Settings Disabled' }
        'ComputerSettingsDisabled' { 'Computer Settings Disabled' }
        'AllSettingsDisabled'      { 'All Settings Disabled' }
        default                    { $gpo.GpoStatus.ToString() }
    }

    # ── Aggregate ────────────────────────────────────────────────────
    [void]$gpoDataList.Add([PSCustomObject]@{
        Name               = $gpo.DisplayName
        Id                 = $gpo.Id.ToString()
        Status             = $gpoStatus
        CreationTime       = $gpo.CreationTime
        ModificationTime   = $gpo.ModificationTime
        Links              = $links
        SecurityFilter     = $securityFilter
        Delegation         = $delegation
        WmiFilterName      = $wmiFilterName
        WmiFilterQuery     = $wmiFilterQuery
        ComputerConfigured = $computerConfigured
        UserConfigured     = $userConfigured
        SettingsHtml       = $settingsHtml
        ComputerEnabled    = ($gpoStatus -notin @('Computer Settings Disabled','All Settings Disabled'))
        UserEnabled        = ($gpoStatus -notin @('User Settings Disabled','All Settings Disabled'))
    })
}
Write-Progress -Activity "Processing GPOs" -Completed

# ─────────────────────────────────────────────────────────────────────────────
# Region: Issue Analysis
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[3/6] Analyzing potential issues..." -ForegroundColor Yellow

$unlinkedGPOs    = @($gpoDataList | Where-Object { $_.Links.Count -eq 0 })
$staleGPOs       = @($gpoDataList | Where-Object { $_.ModificationTime -lt $staleDate })
$emptyGPOs       = @($gpoDataList | Where-Object { -not $_.ComputerConfigured -and -not $_.UserConfigured })
$broadFilterGPOs = @($gpoDataList | Where-Object {
    $_.SecurityFilter | Where-Object {
        $_.Trustee -in @('Authenticated Users', 'Domain Computers', 'Everyone', 'Domain Users')
    }
})
$disabledGPOs = @($gpoDataList | Where-Object { $_.Status -eq 'All Settings Disabled' })

# ── Conflict Detection (FIX #2 — uses cached XML, zero extra API calls) ─────
Write-Host "[4/6] Detecting potential setting conflicts..." -ForegroundColor Yellow

$extensionMap = @{}
foreach ($gpoData in $gpoDataList) {
    $cachedXml = $gpoXmlCache[$gpoData.Id]
    if (-not $cachedXml) { continue }

    try {
        $ns2 = New-Object System.Xml.XmlNamespaceManager($cachedXml.NameTable)
        $ns2.AddNamespace("gp", "http://www.microsoft.com/GroupPolicy/Settings")

        foreach ($section in @("Computer", "User")) {
            $extNodes = $cachedXml.SelectNodes("//gp:$section/gp:ExtensionData/gp:Extension", $ns2)
            foreach ($ext in $extNodes) {
                $extType = $ext.GetAttribute("xsi:type")
                if (-not $extType) { $extType = $ext.LocalName }
                $key = "$section`:$extType"
                if (-not $extensionMap.ContainsKey($key)) {
                    $extensionMap[$key] = [System.Collections.ArrayList]::new()
                }
                if ($extensionMap[$key] -notcontains $gpoData.Name) {
                    [void]$extensionMap[$key].Add($gpoData.Name)
                }
            }
        }
    } catch {
        Add-ScriptError $gpoData.Name "ConflictDetection" $_.Exception.Message
    }
}

# Free the XML cache — can be hundreds of MB in large domains
$gpoXmlCache.Clear()
$gpoXmlCache = $null
[System.GC]::Collect()

$conflicts = [System.Collections.ArrayList]::new()
foreach ($key in $extensionMap.Keys) {
    if ($extensionMap[$key].Count -gt 1) {
        [void]$conflicts.Add([PSCustomObject]@{
            SettingArea = $key
            GPOs        = $extensionMap[$key] -join ", "
            Count       = $extensionMap[$key].Count
        })
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Region: HTML Report Generation
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[5/6] Building HTML report..." -ForegroundColor Yellow

# ── CSS ──────────────────────────────────────────────────────────────────────
$css = @'
<style>
    :root {
        --bg-primary: #0f172a;
        --bg-secondary: #1e293b;
        --bg-card: #1e293b;
        --bg-card-hover: #263348;
        --bg-sidebar: #0c1322;
        --border-color: #334155;
        --text-primary: #f1f5f9;
        --text-secondary: #94a3b8;
        --text-muted: #64748b;
        --accent-blue: #3b82f6;
        --accent-blue-dim: #1e3a5f;
        --accent-green: #22c55e;
        --accent-green-dim: #14532d;
        --accent-red: #ef4444;
        --accent-red-dim: #7f1d1d;
        --accent-amber: #f59e0b;
        --accent-amber-dim: #78350f;
        --accent-purple: #a855f7;
        --accent-purple-dim: #581c87;
        --accent-cyan: #06b6d4;
        --font-sans: 'Segoe UI', system-ui, -apple-system, sans-serif;
        --font-mono: 'Cascadia Code', 'Fira Code', Consolas, monospace;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    html { scroll-behavior: smooth; }

    body {
        font-family: var(--font-sans);
        background: var(--bg-primary);
        color: var(--text-primary);
        line-height: 1.6;
        display: flex;
        min-height: 100vh;
    }

    /* ── Sidebar ─────────────────────────────────── */
    #sidebar {
        width: 300px;
        min-width: 300px;
        background: var(--bg-sidebar);
        border-right: 1px solid var(--border-color);
        height: 100vh;
        position: fixed;
        overflow-y: auto;
        z-index: 100;
        display: flex;
        flex-direction: column;
    }
    #sidebar .sidebar-header {
        padding: 24px 20px 16px;
        border-bottom: 1px solid var(--border-color);
    }
    #sidebar .sidebar-header h2 {
        font-size: 14px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 1.5px;
        color: var(--accent-blue);
        margin-bottom: 4px;
    }
    #sidebar .sidebar-header .domain-name {
        font-size: 12px;
        color: var(--text-muted);
        font-family: var(--font-mono);
    }
    #sidebar .search-box {
        padding: 12px 20px;
        border-bottom: 1px solid var(--border-color);
    }
    #sidebar .search-box input {
        width: 100%;
        padding: 8px 12px;
        border: 1px solid var(--border-color);
        border-radius: 6px;
        background: var(--bg-secondary);
        color: var(--text-primary);
        font-size: 13px;
        outline: none;
        transition: border-color .2s;
    }
    #sidebar .search-box input:focus { border-color: var(--accent-blue); }
    #sidebar .nav-section { padding: 12px 0; }
    #sidebar .nav-section-title {
        padding: 4px 20px;
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: var(--text-muted);
    }
    #sidebar a {
        display: block;
        padding: 6px 20px 6px 28px;
        color: var(--text-secondary);
        text-decoration: none;
        font-size: 13px;
        border-left: 3px solid transparent;
        transition: all .15s;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }
    #sidebar a:hover,
    #sidebar a.active {
        background: var(--bg-card-hover);
        color: var(--text-primary);
        border-left-color: var(--accent-blue);
    }
    #sidebar a .issue-nav-dot {
        display: inline-block;
        width: 7px; height: 7px;
        border-radius: 50%;
        margin-right: 6px;
        vertical-align: middle;
    }

    /* ── Main Content ────────────────────────────── */
    #main {
        margin-left: 300px;
        flex: 1;
        padding: 40px 48px 80px;
        max-width: 1200px;
    }

    h1 {
        font-size: 28px;
        font-weight: 700;
        margin-bottom: 4px;
        color: var(--text-primary);
    }
    .report-meta {
        font-size: 13px;
        color: var(--text-muted);
        margin-bottom: 32px;
    }

    /* ── Summary Cards ───────────────────────────── */
    .summary-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 16px;
        margin-bottom: 36px;
    }
    .summary-card {
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 10px;
        padding: 20px;
        transition: transform .15s, border-color .15s;
    }
    .summary-card:hover { transform: translateY(-2px); border-color: var(--accent-blue); }
    .summary-card .card-value {
        font-size: 32px;
        font-weight: 700;
        line-height: 1.1;
    }
    .summary-card .card-label {
        font-size: 13px;
        color: var(--text-muted);
        margin-top: 4px;
    }
    .summary-card.blue   .card-value { color: var(--accent-blue); }
    .summary-card.green  .card-value { color: var(--accent-green); }
    .summary-card.amber  .card-value { color: var(--accent-amber); }
    .summary-card.red    .card-value { color: var(--accent-red); }
    .summary-card.purple .card-value { color: var(--accent-purple); }

    /* ── Section Headers ─────────────────────────── */
    .section-header {
        font-size: 20px;
        font-weight: 700;
        margin: 40px 0 16px;
        padding-bottom: 8px;
        border-bottom: 2px solid var(--border-color);
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .section-header .icon {
        width: 28px; height: 28px;
        border-radius: 6px;
        display: flex; align-items: center; justify-content: center;
        font-size: 14px;
    }

    /* ── GPO Card ─────────────────────────────────── */
    .gpo-card {
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 10px;
        margin-bottom: 16px;
        overflow: hidden;
        transition: border-color .2s;
    }
    .gpo-card:hover { border-color: var(--accent-blue); }
    .gpo-card-header {
        padding: 16px 20px;
        cursor: pointer;
        display: flex;
        justify-content: space-between;
        align-items: center;
        user-select: none;
    }
    .gpo-card-header:hover { background: var(--bg-card-hover); }
    .gpo-card-header .gpo-title {
        font-size: 15px;
        font-weight: 600;
    }
    .gpo-card-header .gpo-guid {
        font-size: 11px;
        font-family: var(--font-mono);
        color: var(--text-muted);
        margin-top: 2px;
    }
    .gpo-card-header .chevron {
        font-size: 18px;
        color: var(--text-muted);
        transition: transform .2s;
    }
    .gpo-card.open .chevron { transform: rotate(90deg); }
    .gpo-card-body { display: none; padding: 0 20px 20px; }
    .gpo-card.open .gpo-card-body { display: block; }

    /* ── Badges / Pills ──────────────────────────── */
    .badge {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 999px;
        font-size: 11px;
        font-weight: 600;
        letter-spacing: .3px;
        vertical-align: middle;
    }
    .badge-green  { background: var(--accent-green-dim); color: var(--accent-green); }
    .badge-red    { background: var(--accent-red-dim);   color: var(--accent-red); }
    .badge-amber  { background: var(--accent-amber-dim); color: var(--accent-amber); }
    .badge-blue   { background: var(--accent-blue-dim);  color: var(--accent-blue); }
    .badge-purple { background: var(--accent-purple-dim); color: var(--accent-purple); }

    /* ── Detail Tables ───────────────────────────── */
    .detail-section { margin-top: 16px; }
    .detail-section h4 {
        font-size: 13px;
        text-transform: uppercase;
        letter-spacing: .8px;
        color: var(--accent-cyan);
        margin-bottom: 8px;
        display: flex;
        align-items: center;
        gap: 6px;
    }
    table.detail {
        width: 100%;
        border-collapse: collapse;
        font-size: 13px;
    }
    table.detail th {
        text-align: left;
        padding: 8px 12px;
        background: rgba(255,255,255,.04);
        color: var(--text-muted);
        font-weight: 600;
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: .5px;
        border-bottom: 1px solid var(--border-color);
    }
    table.detail td {
        padding: 8px 12px;
        border-bottom: 1px solid rgba(255,255,255,.04);
        color: var(--text-secondary);
        vertical-align: top;
    }
    table.detail tr:last-child td { border-bottom: none; }
    table.detail tr:hover td { background: rgba(255,255,255,.02); }
    .mono { font-family: var(--font-mono); font-size: 12px; }

    /* ── Issues Section ──────────────────────────── */
    .issue-group {
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 10px;
        margin-bottom: 16px;
        overflow: hidden;
    }
    .issue-group-header {
        padding: 14px 20px;
        display: flex;
        align-items: center;
        gap: 12px;
        cursor: pointer;
        user-select: none;
    }
    .issue-group-header:hover { background: var(--bg-card-hover); }
    .issue-group-header .issue-icon {
        width: 32px; height: 32px;
        border-radius: 8px;
        display: flex; align-items: center; justify-content: center;
        font-size: 16px; font-weight: 700;
    }
    .issue-group-header .issue-title { font-weight: 600; font-size: 14px; }
    .issue-group-header .issue-count {
        margin-left: auto;
        font-size: 13px;
        color: var(--text-muted);
    }
    .issue-group-body { display: none; padding: 0 20px 16px; }
    .issue-group.open .issue-group-body { display: block; }
    .issue-list { list-style: none; }
    .issue-list li {
        padding: 6px 0;
        font-size: 13px;
        color: var(--text-secondary);
        border-bottom: 1px solid rgba(255,255,255,.04);
    }
    .issue-list li:last-child { border-bottom: none; }

    /* ── Error Log ───────────────────────────────── */
    .error-log {
        background: var(--accent-red-dim);
        border: 1px solid var(--accent-red);
        border-radius: 10px;
        padding: 16px 20px;
        margin-bottom: 24px;
    }
    .error-log h4 { color: var(--accent-red); margin-bottom: 8px; }

    /* ── Settings embed ──────────────────────────── */
    .settings-embed {
        background: rgba(0,0,0,.2);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 16px;
        margin-top: 8px;
        max-height: 500px;
        overflow: auto;
        font-size: 12px;
    }
    .settings-embed table { font-size: 12px; }

    /* ── Utility ──────────────────────────────────── */
    .text-muted { color: var(--text-muted); }
    .warning { color: var(--accent-amber); }
    .no-data {
        padding: 20px;
        text-align: center;
        color: var(--text-muted);
        font-style: italic;
    }

    /* ── Print ────────────────────────────────────── */
    @media print {
        #sidebar { display: none; }
        #main { margin-left: 0; padding: 20px; }
        .gpo-card-body { display: block !important; }
        .issue-group-body { display: block !important; }
        body { background: #fff; color: #1a1a1a; }
    }
</style>
'@

# ── JavaScript ───────────────────────────────────────────────────────────────
$js = @'
<script>
    // Toggle expandable cards
    document.addEventListener('click', function(e) {
        var header = e.target.closest('.gpo-card-header, .issue-group-header');
        if (header) {
            var card = header.parentElement;
            card.classList.toggle('open');
        }
    });

    // Sidebar search / filter
    document.getElementById('sidebarSearch').addEventListener('input', function() {
        var q = this.value.toLowerCase();
        document.querySelectorAll('#sidebar .nav-section a').forEach(function(a) {
            a.style.display = a.textContent.toLowerCase().includes(q) ? '' : 'none';
        });
    });

    // Expand all / Collapse all
    function toggleAll(expand) {
        document.querySelectorAll('.gpo-card').forEach(function(c) {
            expand ? c.classList.add('open') : c.classList.remove('open');
        });
    }
</script>
'@

# ── Helper: HTML-encode ─────────────────────────────────────────────────────
function HtmlEncode([string]$s) { return [System.Net.WebUtility]::HtmlEncode($s) }

# ── Helper: Build a detail table ─────────────────────────────────────────────
function Build-DetailTable {
    param([string]$Title, [string[]]$Columns, [System.Collections.IEnumerable]$Rows, [scriptblock]$RowRenderer)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("<div class='detail-section'><h4>$Title</h4>")
    if (-not $Rows -or @($Rows).Count -eq 0) {
        [void]$sb.Append("<p class='no-data'>No data available</p></div>")
        return $sb.ToString()
    }
    [void]$sb.Append("<table class='detail'><thead><tr>")
    foreach ($col in $Columns) { [void]$sb.Append("<th>$col</th>") }
    [void]$sb.Append("</tr></thead><tbody>")
    foreach ($row in $Rows) { $rendered = & $RowRenderer $row; [void]$sb.Append($rendered) }
    [void]$sb.Append("</tbody></table></div>")
    return $sb.ToString()
}

# ─────────────────────────────────────────────────────────────────────────────
# Region: Build the HTML Document
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[6/6] Writing HTML file..." -ForegroundColor Yellow

$html = [System.Text.StringBuilder]::new()
[void]$html.Append(@"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>GPO Audit Report – $(HtmlEncode $DomainName)</title>
$css
</head>
<body>

<!-- ═══════════════ SIDEBAR ═══════════════ -->
<nav id="sidebar">
    <div class="sidebar-header">
        <h2>GPO Audit</h2>
        <div class="domain-name">$(HtmlEncode $DomainName)</div>
    </div>
    <div class="search-box">
        <input type="text" id="sidebarSearch" placeholder="Filter GPOs…" />
    </div>
    <div class="nav-section">
        <div class="nav-section-title">Overview</div>
        <a href="#summary">Executive Summary</a>
        <a href="#issues">Potential Issues</a>
    </div>
    <div class="nav-section">
        <div class="nav-section-title">GPOs ($totalGPOs)</div>
"@)

# Sidebar links
foreach ($g in $gpoDataList) {
    $anchor = "gpo-" + ($g.Id -replace '[{}]','')
    $dot = if ($g.Links.Count -eq 0) {
        "<span class='issue-nav-dot' style='background:var(--accent-amber)' title='Unlinked'></span>"
    } elseif ($g.Status -eq 'All Settings Disabled') {
        "<span class='issue-nav-dot' style='background:var(--accent-red)' title='Disabled'></span>"
    } else { "" }
    [void]$html.Append("        <a href='#$anchor'>$dot$(HtmlEncode $g.Name)</a>`n")
}

[void]$html.Append(@"
    </div>
</nav>

<!-- ═══════════════ MAIN CONTENT ═══════════════ -->
<div id="main">

<h1>Group Policy Audit Report</h1>
<p class="report-meta">Generated $(Get-Date -Format 'dddd, MMMM dd, yyyy HH:mm:ss') &nbsp;|&nbsp; Domain: <strong>$(HtmlEncode $DomainName)</strong></p>
"@)

# ── FIX #6 — Error banner in HTML if any GPOs had collection errors ──────────
if ($script:errorCount -gt 0) {
    [void]$html.Append(@"
<div class="error-log">
    <h4>&#x26A0; $($script:errorCount) collection error(s) encountered</h4>
    <p style="font-size:13px;color:var(--text-secondary);margin-bottom:8px;">
        Some GPOs could not be fully documented. Data may be incomplete for these objects.
    </p>
    <table class="detail">
        <thead><tr><th>Time</th><th>GPO</th><th>Phase</th><th>Error</th></tr></thead>
        <tbody>
"@)
    foreach ($err in $script:errorLog) {
        [void]$html.Append("<tr><td class='mono'>$($err.Time)</td><td>$(HtmlEncode $err.GPO)</td><td>$($err.Phase)</td><td class='text-muted'>$(HtmlEncode $err.Error)</td></tr>")
    }
    [void]$html.Append("</tbody></table></div>")
}

# ── Executive Summary ────────────────────────────────────────────────────────
$linkedCount = ($gpoDataList | Where-Object { $_.Links.Count -gt 0 } | Measure-Object).Count

[void]$html.Append(@"
<div id="summary">
    <div class="section-header">
        <span class="icon" style="background:var(--accent-blue-dim);color:var(--accent-blue);">&#x1F4CA;</span>
        Executive Summary
    </div>
    <div class="summary-grid">
        <div class="summary-card blue">
            <div class="card-value">$totalGPOs</div>
            <div class="card-label">Total GPOs</div>
        </div>
        <div class="summary-card green">
            <div class="card-value">$linkedCount</div>
            <div class="card-label">Linked GPOs</div>
        </div>
        <div class="summary-card amber">
            <div class="card-value">$($unlinkedGPOs | Measure-Object | Select-Object -ExpandProperty Count)</div>
            <div class="card-label">Unlinked GPOs</div>
        </div>
        <div class="summary-card red">
            <div class="card-value">$($staleGPOs | Measure-Object | Select-Object -ExpandProperty Count)</div>
            <div class="card-label">Stale ($StaleThresholdDays+ days)</div>
        </div>
        <div class="summary-card purple">
            <div class="card-value">$($emptyGPOs | Measure-Object | Select-Object -ExpandProperty Count)</div>
            <div class="card-label">No Settings Configured</div>
        </div>
    </div>
</div>
"@)

# ── Issues Section ───────────────────────────────────────────────────────────
[void]$html.Append(@"
<div id="issues">
    <div class="section-header">
        <span class="icon" style="background:var(--accent-amber-dim);color:var(--accent-amber);">&#x26A0;</span>
        Potential Issues
    </div>
"@)

# Issue 1: Unlinked GPOs
[void]$html.Append("<div class='issue-group'><div class='issue-group-header'>")
[void]$html.Append("<div class='issue-icon' style='background:var(--accent-amber-dim);color:var(--accent-amber);'>&#x1F517;</div>")
[void]$html.Append("<span class='issue-title'>Unlinked GPOs</span>")
[void]$html.Append("<span class='issue-count'>$($unlinkedGPOs.Count) found</span></div>")
[void]$html.Append("<div class='issue-group-body'><ul class='issue-list'>")
if ($unlinkedGPOs.Count -eq 0) {
    [void]$html.Append("<li class='text-muted'>None detected – all GPOs are linked.</li>")
} else {
    foreach ($u in $unlinkedGPOs) {
        [void]$html.Append("<li><strong>$(HtmlEncode $u.Name)</strong> <span class='text-muted mono'>($($u.Id))</span> – last modified $(($u.ModificationTime).ToString('yyyy-MM-dd'))</li>")
    }
}
[void]$html.Append("</ul></div></div>")

# Issue 2: Stale GPOs
[void]$html.Append("<div class='issue-group'><div class='issue-group-header'>")
[void]$html.Append("<div class='issue-icon' style='background:var(--accent-red-dim);color:var(--accent-red);'>&#x23F3;</div>")
[void]$html.Append("<span class='issue-title'>Stale GPOs (not modified in $StaleThresholdDays+ days)</span>")
[void]$html.Append("<span class='issue-count'>$($staleGPOs.Count) found</span></div>")
[void]$html.Append("<div class='issue-group-body'><ul class='issue-list'>")
if ($staleGPOs.Count -eq 0) {
    [void]$html.Append("<li class='text-muted'>None detected.</li>")
} else {
    foreach ($s in $staleGPOs) {
        $age = [math]::Round(($today - $s.ModificationTime).TotalDays)
        [void]$html.Append("<li><strong>$(HtmlEncode $s.Name)</strong> – last modified $(($s.ModificationTime).ToString('yyyy-MM-dd')) ($age days ago)</li>")
    }
}
[void]$html.Append("</ul></div></div>")

# Issue 3: Empty GPOs
[void]$html.Append("<div class='issue-group'><div class='issue-group-header'>")
[void]$html.Append("<div class='issue-icon' style='background:var(--accent-purple-dim);color:var(--accent-purple);'>&#x1F4AD;</div>")
[void]$html.Append("<span class='issue-title'>GPOs With No Settings Configured</span>")
[void]$html.Append("<span class='issue-count'>$($emptyGPOs.Count) found</span></div>")
[void]$html.Append("<div class='issue-group-body'><ul class='issue-list'>")
if ($emptyGPOs.Count -eq 0) {
    [void]$html.Append("<li class='text-muted'>None detected.</li>")
} else {
    foreach ($e in $emptyGPOs) {
        [void]$html.Append("<li><strong>$(HtmlEncode $e.Name)</strong> <span class='badge badge-amber'>Empty</span></li>")
    }
}
[void]$html.Append("</ul></div></div>")

# Issue 4: Broad Security Filtering
[void]$html.Append("<div class='issue-group'><div class='issue-group-header'>")
[void]$html.Append("<div class='issue-icon' style='background:var(--accent-blue-dim);color:var(--accent-blue);'>&#x1F310;</div>")
[void]$html.Append("<span class='issue-title'>Overly Broad Security Filtering</span>")
[void]$html.Append("<span class='issue-count'>$($broadFilterGPOs.Count) found</span></div>")
[void]$html.Append("<div class='issue-group-body'><ul class='issue-list'>")
if ($broadFilterGPOs.Count -eq 0) {
    [void]$html.Append("<li class='text-muted'>None detected.</li>")
} else {
    foreach ($b in $broadFilterGPOs) {
        $broadNames = ($b.SecurityFilter | Where-Object {
            $_.Trustee -in @('Authenticated Users','Domain Computers','Everyone','Domain Users')
        } | ForEach-Object { $_.Trustee }) -join ", "
        [void]$html.Append("<li><strong>$(HtmlEncode $b.Name)</strong> applies to: <span class='badge badge-blue'>$broadNames</span></li>")
    }
}
[void]$html.Append("</ul></div></div>")

# Issue 5: Potential Conflicts
[void]$html.Append("<div class='issue-group'><div class='issue-group-header'>")
[void]$html.Append("<div class='issue-icon' style='background:var(--accent-red-dim);color:var(--accent-red);'>&#x26A1;</div>")
[void]$html.Append("<span class='issue-title'>Potential Setting Conflicts (overlapping policy areas)</span>")
[void]$html.Append("<span class='issue-count'>$($conflicts.Count) areas</span></div>")
[void]$html.Append("<div class='issue-group-body'>")
if ($conflicts.Count -eq 0) {
    [void]$html.Append("<p class='no-data'>No overlapping policy areas detected.</p>")
} else {
    [void]$html.Append("<table class='detail'><thead><tr><th>Setting Area</th><th>GPOs</th><th>Count</th></tr></thead><tbody>")
    foreach ($c in $conflicts) {
        [void]$html.Append("<tr><td class='mono'>$(HtmlEncode $c.SettingArea)</td><td>$(HtmlEncode $c.GPOs)</td><td>$($c.Count)</td></tr>")
    }
    [void]$html.Append("</tbody></table>")
}
[void]$html.Append("</div></div>")

[void]$html.Append("</div>") # close #issues

# ── GPO Detail Cards ────────────────────────────────────────────────────────
[void]$html.Append(@"
<div id="gpo-details">
    <div class="section-header" style="justify-content:space-between;">
        <span style="display:flex;align-items:center;gap:10px;">
            <span class="icon" style="background:var(--accent-green-dim);color:var(--accent-green);">&#x1F4C1;</span>
            GPO Details
        </span>
        <span style="font-size:12px;font-weight:400;">
            <a href="javascript:toggleAll(true)" style="color:var(--accent-blue);cursor:pointer;text-decoration:none;">Expand All</a>
            &nbsp;|&nbsp;
            <a href="javascript:toggleAll(false)" style="color:var(--accent-blue);cursor:pointer;text-decoration:none;">Collapse All</a>
        </span>
    </div>
"@)

foreach ($g in $gpoDataList) {
    $anchor = "gpo-" + ($g.Id -replace '[{}]','')
    $statusBadge = switch -Wildcard ($g.Status) {
        'All Settings Enabled'  { "<span class='badge badge-green'>All Enabled</span>" }
        'All Settings Disabled' { "<span class='badge badge-red'>All Disabled</span>" }
        '*User*Disabled*'       { "<span class='badge badge-amber'>User Disabled</span>" }
        '*Computer*Disabled*'   { "<span class='badge badge-amber'>Computer Disabled</span>" }
        default                 { "<span class='badge badge-blue'>$($g.Status)</span>" }
    }

    [void]$html.Append(@"
    <div class="gpo-card" id="$anchor">
        <div class="gpo-card-header">
            <div>
                <div class="gpo-title">$(HtmlEncode $g.Name) &nbsp;$statusBadge</div>
                <div class="gpo-guid">{$($g.Id)}</div>
            </div>
            <span class="chevron">&#x25B6;</span>
        </div>
        <div class="gpo-card-body">
"@)

    # Metadata
    [void]$html.Append(@"
            <div class="detail-section"><h4>&#x1F4C5; Metadata</h4>
            <table class="detail">
                <tr><td style="width:200px;color:var(--text-muted);">Created</td><td>$(($g.CreationTime).ToString('yyyy-MM-dd HH:mm:ss'))</td></tr>
                <tr><td style="color:var(--text-muted);">Last Modified</td><td>$(($g.ModificationTime).ToString('yyyy-MM-dd HH:mm:ss'))</td></tr>
                <tr><td style="color:var(--text-muted);">Computer Configuration</td><td>$(if($g.ComputerEnabled){"<span class='badge badge-green'>Enabled</span>"}else{"<span class='badge badge-red'>Disabled</span>"}) $(if($g.ComputerConfigured){"– <em>has settings</em>"}else{"– <em>no settings</em>"})</td></tr>
                <tr><td style="color:var(--text-muted);">User Configuration</td><td>$(if($g.UserEnabled){"<span class='badge badge-green'>Enabled</span>"}else{"<span class='badge badge-red'>Disabled</span>"}) $(if($g.UserConfigured){"– <em>has settings</em>"}else{"– <em>no settings</em>"})</td></tr>
                <tr><td style="color:var(--text-muted);">WMI Filter</td><td>$(if($g.WmiFilterName -ne 'None'){"<span class='badge badge-purple'>$(HtmlEncode $g.WmiFilterName)</span><br/><span class='mono text-muted'>$(HtmlEncode $g.WmiFilterQuery)</span>"}else{"<span class='text-muted'>None</span>"})</td></tr>
            </table></div>
"@)

    # Links
    $linksHtml = Build-DetailTable -Title "&#x1F517; Link Locations" `
        -Columns @('Path','Link Enabled','Enforced') `
        -Rows $g.Links `
        -RowRenderer {
            param($r)
            $enBadge  = if ($r.Enabled  -eq 'true') { "<span class='badge badge-green'>Yes</span>" } else { "<span class='badge badge-red'>No</span>" }
            $enfBadge = if ($r.Enforced -eq 'true') { "<span class='badge badge-amber'>Enforced</span>" } else { "<span class='text-muted'>No</span>" }
            "<tr><td class='mono'>$(HtmlEncode $r.Path)</td><td>$enBadge</td><td>$enfBadge</td></tr>"
        }
    [void]$html.Append($linksHtml)

    # Security Filtering
    $secHtml = Build-DetailTable -Title "&#x1F512; Security Filtering" `
        -Columns @('Trustee','Type','Permission') `
        -Rows $g.SecurityFilter `
        -RowRenderer {
            param($r)
            "<tr><td>$(HtmlEncode $r.Trustee)</td><td class='text-muted'>$($r.TrusteeType)</td><td>$($r.Permission)</td></tr>"
        }
    [void]$html.Append($secHtml)

    # Delegation
    $delHtml = Build-DetailTable -Title "&#x1F465; Delegation Permissions" `
        -Columns @('Trustee','Type','Permission','Inherited') `
        -Rows $g.Delegation `
        -RowRenderer {
            param($r)
            $inhBadge = if ($r.Inherited) { "<span class='text-muted'>Yes</span>" } else { "No" }
            "<tr><td>$(HtmlEncode $r.Trustee)</td><td class='text-muted'>$($r.TrusteeType)</td><td>$($r.Permission)</td><td>$inhBadge</td></tr>"
        }
    [void]$html.Append($delHtml)

    # Settings detail (if requested)
    if ($IncludeSettingsDetail -and $g.SettingsHtml) {
        [void]$html.Append(@"
            <div class="detail-section"><h4>&#x2699; Configured Settings (Full Detail)</h4>
            <div class="settings-embed">$($g.SettingsHtml)</div></div>
"@)
    }

    [void]$html.Append("</div></div>") # close card-body, gpo-card
}

[void]$html.Append("</div>") # close #gpo-details

# ── Footer ───────────────────────────────────────────────────────────────────
$errorNote = if ($script:errorCount -gt 0) { " | $($script:errorCount) error(s) during collection" } else { "" }

[void]$html.Append(@"
<div style="margin-top:60px;padding-top:20px;border-top:1px solid var(--border-color);text-align:center;">
    <p class="text-muted" style="font-size:12px;">
        GPO Audit Report &mdash; Export-GPOReport.ps1 v4.0 &mdash; $(Get-Date -Format 'yyyy-MM-dd HH:mm')$errorNote
    </p>
</div>
</div><!-- /main -->
$js
</body>
</html>
"@)

# ─────────────────────────────────────────────────────────────────────────────
# Region: Write File & Exit
# ─────────────────────────────────────────────────────────────────────────────
try {
    $html.ToString() | Out-File -FilePath $reportFile -Encoding UTF8 -Force
} catch {
    Write-Error "FATAL: Cannot write report file — $_"
    exit 1
}

$fileSize = [math]::Round((Get-Item $reportFile).Length / 1KB)

# ── Console Summary ──────────────────────────────────────────────────────────
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " Report Complete" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  File    : $reportFile  ($fileSize KB)" -ForegroundColor Green
Write-Host "  GPOs    : $totalGPOs documented" -ForegroundColor Green
Write-Host "  Errors  : $($script:errorCount)" -ForegroundColor $(if($script:errorCount -gt 0){'Yellow'}else{'Green'})
Write-Host ""
Write-Host "  Issues Found:" -ForegroundColor White
Write-Host "    Unlinked        : $($unlinkedGPOs.Count)" -ForegroundColor $(if($unlinkedGPOs.Count -gt 0){'Yellow'}else{'DarkGray'})
Write-Host "    Stale ($($StaleThresholdDays)+ days): $($staleGPOs.Count)" -ForegroundColor $(if($staleGPOs.Count -gt 0){'Yellow'}else{'DarkGray'})
Write-Host "    Empty settings  : $($emptyGPOs.Count)" -ForegroundColor $(if($emptyGPOs.Count -gt 0){'Yellow'}else{'DarkGray'})
Write-Host "    Broad filtering : $($broadFilterGPOs.Count)" -ForegroundColor $(if($broadFilterGPOs.Count -gt 0){'Yellow'}else{'DarkGray'})
Write-Host "    Conflict areas  : $($conflicts.Count)" -ForegroundColor $(if($conflicts.Count -gt 0){'Yellow'}else{'DarkGray'})
Write-Host ""

# FIX #6 — Print error details to console
if ($script:errorCount -gt 0) {
    Write-Host "  Error Details:" -ForegroundColor Yellow
    foreach ($err in $script:errorLog) {
        Write-Host "    [$($err.Time)] $($err.GPO) — $($err.Phase): $($err.Error)" -ForegroundColor DarkYellow
    }
    Write-Host ""
}

# FIX #5 — Proper exit codes for callers (Task Scheduler, CI, wrapper script)
# Exit 0 = success, Exit 1 = fatal (used above), Exit 2 = partial success
if ($script:errorCount -gt 0) {
    Write-Host "  Exit code 2 — partial success ($($script:errorCount) GPO errors)" -ForegroundColor Yellow
    exit 2
}

Write-Host "  Exit code 0 — all GPOs documented successfully" -ForegroundColor Green
exit 0
