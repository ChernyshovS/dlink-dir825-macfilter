<#
.SYNOPSIS
    Block / unblock devices on a D-Link DIR-825ACG1 by MAC address.

.DESCRIPTION
    Talks to the router's JSON-RPC API (POST /jsonrpc) using the same custom
    HTTP Digest scheme its web UI uses (header "anweb-authenticate").
    It edits the firewall MAC filter (config id 74), which applies to BOTH
    wired and wireless clients.

    A blocked device can still associate with Wi-Fi and get a DHCP lease,
    but no traffic is routed for it -- no internet.

.EXAMPLE
    .\dlink-macfilter.ps1 setup
    .\dlink-macfilter.ps1 status
    .\dlink-macfilter.ps1 dump
    .\dlink-macfilter.ps1 block   -Mac AA:BB:CC:DD:EE:01
    .\dlink-macfilter.ps1 unblock -Name tv
    .\dlink-macfilter.ps1 toggle  -Name tv
    .\dlink-macfilter.ps1 remove  -Mac AA:BB:CC:DD:EE:01
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('status', 'block', 'unblock', 'toggle', 'dump', 'setup', 'remove')]
    [string]$Action = 'status',

    [string]$Mac,
    [string]$Name,
    [string]$Router = '192.168.0.1',
    [string]$User   = 'admin',

    # Allow blocking a MAC that belongs to this computer (normally refused).
    [switch]$Force,

    # setup only: skip creating the desktop shortcut for the picker window.
    [switch]$NoShortcut
)

$ErrorActionPreference = 'Stop'

$CONFIG_ID = 74                      # firewall MAC filter
$StateDir  = $PSScriptRoot           # state lives next to this script
$CredFile  = Join-Path $StateDir 'cred.xml'
$DevFile   = Join-Path $StateDir 'devices.json'

# Authentication and config read/write live in the shared module, so the
# protocol is implemented once for every script in this folder.
. (Join-Path $PSScriptRoot 'router-api.ps1')
Initialize-RouterApi -Router $Router -User $User -CredFile $CredFile

# ---------------------------------------------------------------- helpers ---

function Get-StoredCredential {
    if (-not (Test-Path $CredFile)) {
        Write-Host 'Router password is not stored yet.' -ForegroundColor Yellow
        Write-Host 'Enter the admin password of the router. It is encrypted with'
        Write-Host 'Windows DPAPI and readable only by your account on this machine,'
        Write-Host 'even though the file sits next to the script.'
        $cred = Get-Credential -UserName $User -Message "D-Link $Router"
        $cred | Export-Clixml -Path $CredFile
        Write-Host "Saved to $CredFile" -ForegroundColor Green
    }
    Import-Clixml -Path $CredFile
}

function New-PickerShortcut {
    <#  One desktop shortcut, created once at setup: the picker window is the
        way this tool is normally used, and everything else lives inside it.

        -ExecutionPolicy Bypass is baked in, so the shortcut works on a
        machine where scripts are otherwise disallowed. -WindowStyle Hidden
        keeps the console out of the way -- only the window shows. #>
    $picker = Join-Path $PSScriptRoot 'pick-devices.ps1'
    if (-not (Test-Path $picker)) {
        Write-Host 'pick-devices.ps1 not found next to this script; shortcut skipped.' -ForegroundColor DarkYellow
        return
    }

    $lnkPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Devices.lnk'
    $shell = New-Object -ComObject WScript.Shell
    $lnk = $shell.CreateShortcut($lnkPath)
    $lnk.TargetPath       = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $lnk.Arguments        = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$picker`""
    $lnk.WorkingDirectory = $PSScriptRoot
    $lnk.Description      = 'Pick devices to block or to keep on the Wi-Fi whitelist'
    $lnk.IconLocation     = "$env:SystemRoot\System32\shell32.dll,18"
    $lnk.Save()
    Write-Host "Shortcut created: $lnkPath" -ForegroundColor Green
}

function Get-Devices {
    if (Test-Path $DevFile) { return (Get-Content $DevFile -Raw | ConvertFrom-Json) }
    return $null
}

function Resolve-Mac {
    param([string]$MacArg, [string]$NameArg)
    if ($MacArg) { return (ConvertTo-RouterMac $MacArg) }
    if ($NameArg) {
        $devices = Get-Devices
        if ($null -eq $devices) { throw 'No device list yet. Run: .\dlink-macfilter.ps1 setup' }
        $entry = $devices.PSObject.Properties | Where-Object { $_.Name -eq $NameArg }
        if (-not $entry) {
            $known = ($devices.PSObject.Properties.Name) -join ', '
            throw "Unknown device name '$NameArg'. Known: $known"
        }
        return (ConvertTo-RouterMac $entry.Value)
    }
    throw 'Specify -Mac <address> or -Name <alias>.'
}

# ------------------------------------------------------------- transport ---
# The digest handshake itself lives in router-api.ps1; these two wrappers
# only know which configuration holds the firewall MAC filter.

function Read-MacFilter {
    $data = Read-RouterConfig -Id $CONFIG_ID
    $mf = $data.macfilter
    if ($null -eq $mf) { throw 'Response contained no macfilter section. Run "dump" and inspect the output.' }
    return @($mf)
}

function Write-MacRule {
    param($Rule, [int]$Pos)
    return (Write-RouterConfig -Id $CONFIG_ID -Data $Rule -Pos $Pos)
}

# ------------------------------------------------------------------ logic ---

function Find-RuleIndex {
    param($Filter, [string]$Target)
    for ($i = 0; $i -lt $Filter.Count; $i++) {
        $m = $Filter[$i].mac
        if ($m -and ([string]$m).ToUpper() -eq $Target) { return $i }
    }
    return -1
}

function New-Rule {
    param($Filter, [string]$Target)

    # Clone the shape of an existing rule so we never invent a field set.
    $template = $null
    foreach ($r in $Filter) { if ($r.mac) { $template = $r; break } }

    $maxId = 0
    foreach ($r in $Filter) { if ([int]$r.id -gt $maxId) { $maxId = [int]$r.id } }

    if ($template) {
        $new = $template | ConvertTo-Json -Depth 10 | ConvertFrom-Json
    } else {
        Write-Host 'No existing rule to copy; using the field set taken from the web UI.' -ForegroundColor DarkYellow
        $new = [pscustomobject]@{ id = 0; state = $true; enable = 'DROP'; mac = ''; hostname = '' }
    }
    $new.id     = $maxId + 1
    $new.mac    = $Target
    $new.state  = $true
    $new.enable = 'DROP'
    if ($null -ne $new.PSObject.Properties['hostname']) { $new.hostname = '' }
    return $new
}

function Initialize-BaseRule {
    <#  The filter starts out completely empty -- not even a default-policy
        entry. The web UI writes that entry at position 0 before appending the
        first real rule, so we do exactly the same. state = $false means
        "allow by default", which keeps this a blacklist. #>
    param($Filter)

    $hasBase = ($Filter.Count -gt 0) -and ($null -eq $Filter[0].mac)
    if ($hasBase) { return $false }

    Write-Host 'MAC filter is empty; creating the default-policy entry (allow by default).' -ForegroundColor DarkGray
    $base = [pscustomobject]@{ id = 0; state = $false; enable = 'DROP'; mac = $null }
    Write-MacRule -Rule $base -Pos 0 | Out-Null
    return $true
}

function Show-Status {
    param($Filter)
    $base = $Filter | Where-Object { $null -eq $_.mac } | Select-Object -First 1
    if ($base) {
        $mode = 'ALLOW by default'
        if ($base.state) { $mode = 'DENY by default (whitelist mode)' }
        Write-Host "Default policy : $mode"
    } else {
        Write-Host 'Default policy : ALLOW by default (filter not initialised yet)'
    }
    $rules = @($Filter | Where-Object { $null -ne $_.mac })
    if ($rules.Count -eq 0) {
        Write-Host 'Rules          : none'
        return
    }
    Write-Host 'Rules          :'
    foreach ($r in $rules) {
        # State of the device, not of the rule. The old "[off] MAC BLOCK"
        # was read as "blocked", while a switched-off rule blocks nothing:
        # unblock keeps the entry so that blocking again costs one request.
        if (-not $r.state) {
            $verdict = 'allowed  (rule kept, switched off)'
            $colour  = 'Gray'
        } elseif ($r.enable -eq 'DROP') {
            $verdict = 'BLOCKED'
            $colour  = 'Red'
        } else {
            $verdict = 'allowed  (rule on)'
            $colour  = 'Green'
        }
        Write-Host ("  {0,-18} {1}" -f $r.mac, $verdict) -ForegroundColor $colour
    }
}

function Remove-Rule {
    <#  Deletes a rule outright, unlike unblock, which only switches it off.

        Switching off is the right default: re-blocking then costs one
        request and the history stays visible. Deletion is for entries that
        will never come back -- a phone with MAC randomisation leaves a new
        dead address behind every time it changes one. #>
    param([string]$Target)

    $filter = Read-MacFilter
    $idx    = Find-RuleIndex -Filter $filter -Target $Target
    if ($idx -lt 0) {
        Write-Host "$Target has no rule -- nothing to remove." -ForegroundColor DarkGray
        return
    }
    # Entry 0 carries the default policy rather than a device. Find-RuleIndex
    # already skips it, but deleting it would silently change how the whole
    # filter behaves, so refuse explicitly.
    if ($null -eq $filter[$idx].mac) {
        throw 'Refusing to delete the default-policy entry.'
    }

    Remove-RouterConfig -Id $CONFIG_ID -Data $filter[$idx] -Pos $idx | Out-Null
    Write-Host "REMOVED  $Target" -ForegroundColor Yellow
}

function Set-Block {
    param([string]$Target, [bool]$Blocked)

    if ($Blocked -and -not $Force) {
        if ((Get-LocalMacAddresses) -contains $Target) {
            throw ("$Target is a network adapter of THIS computer. Blocking it would cut " +
                   "off your own access to the router. Re-run with -Force if you really mean it.")
        }
    }

    $filter = Read-MacFilter

    if ($Blocked) {
        if (Initialize-BaseRule -Filter $filter) { $filter = Read-MacFilter }
    }

    $idx = Find-RuleIndex -Filter $filter -Target $Target

    if ($idx -ge 0) {
        $rule = $filter[$idx] | ConvertTo-Json -Depth 10 | ConvertFrom-Json
        $rule.state  = $Blocked      # rule Enable flag
        $rule.enable = 'DROP'        # rule Action
        $pos = $idx
    } else {
        if (-not $Blocked) {
            Write-Host "$Target is not in the filter -- nothing to unblock." -ForegroundColor DarkGray
            return
        }
        # A rule the router has not seen before is appended with pos = -1,
        # which is exactly what the web UI sends for a newly added rule.
        $rule = New-Rule -Filter $filter -Target $Target
        $pos  = -1
    }

    Write-MacRule -Rule $rule -Pos $pos | Out-Null

    if ($Blocked) {
        Write-Host "BLOCKED  $Target" -ForegroundColor Red
    } else {
        Write-Host "ALLOWED  $Target" -ForegroundColor Green
    }
}

# ---------------------------------------------------------------- actions ---

# The shared module only reads cred.xml; creating it on first use stays here,
# so any action still asks for the password once instead of failing.
Get-StoredCredential | Out-Null

switch ($Action) {

    'setup' {
        Get-StoredCredential | Out-Null
        # An empty object, not a sample entry: the picker window reads this
        # file as a list of devices, so the sample turned up there as a row
        # for a device that does not exist and never will.
        if (-not (Test-Path $DevFile)) {
            '{}' | Set-Content -Path $DevFile -Encoding UTF8
        }
        if (-not $NoShortcut) { New-PickerShortcut }
        Write-Host ''
        Write-Host "Device aliases file: $DevFile"
        Write-Host 'It only holds display names; you normally fill it from the picker window.'
        Write-Host ''
        Write-Host 'Then check the connection with:  .\dlink-macfilter.ps1 status'
    }

    'dump' {
        $r = Invoke-RouterRpc @{ jsonrpc = '2.0'; method = 'read'; params = @{ id = $CONFIG_ID }; id = 1 }
        $r | ConvertTo-Json -Depth 25
    }

    'remove' {
        Remove-Rule -Target (Resolve-Mac -MacArg $Mac -NameArg $Name)
    }

    'status' {
        Show-Status -Filter (Read-MacFilter)
    }

    'block' {
        Set-Block -Target (Resolve-Mac -MacArg $Mac -NameArg $Name) -Blocked $true
    }

    'unblock' {
        Set-Block -Target (Resolve-Mac -MacArg $Mac -NameArg $Name) -Blocked $false
    }

    'toggle' {
        $target = Resolve-Mac -MacArg $Mac -NameArg $Name
        $filter = Read-MacFilter
        $idx    = Find-RuleIndex -Filter $filter -Target $target
        $isBlocked = $false
        if ($idx -ge 0) {
            $isBlocked = ([bool]$filter[$idx].state) -and ($filter[$idx].enable -eq 'DROP')
        }
        Set-Block -Target $target -Blocked (-not $isBlocked)
    }
}
