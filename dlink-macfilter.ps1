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
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('status', 'block', 'unblock', 'toggle', 'dump', 'setup')]
    [string]$Action = 'status',

    [string]$Mac,
    [string]$Name,
    [string]$Router = '192.168.0.1',
    [string]$User   = 'admin',

    # Allow blocking a MAC that belongs to this computer (normally refused).
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Net.Http

$CONFIG_ID = 74                      # firewall MAC filter
$StateDir  = $PSScriptRoot           # state lives next to this script
$CredFile  = Join-Path $StateDir 'cred.xml'
$DevFile   = Join-Path $StateDir 'devices.json'
$Endpoint  = '/jsonrpc'
$BaseUrl   = "http://$Router"

# ---------------------------------------------------------------- helpers ---

function Get-Md5Hex([string]$Text) {
    $md5   = [System.Security.Cryptography.MD5]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    -join ($md5.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })
}

function New-Cnonce {
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    -join (1..16 | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
}

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

function Get-Devices {
    if (Test-Path $DevFile) { return (Get-Content $DevFile -Raw | ConvertFrom-Json) }
    return $null
}

function Resolve-Mac {
    param([string]$MacArg, [string]$NameArg)
    if ($MacArg) { return $MacArg.ToUpper().Replace('-', ':') }
    if ($NameArg) {
        $devices = Get-Devices
        if ($null -eq $devices) { throw 'No device list yet. Run: .\dlink-macfilter.ps1 setup' }
        $entry = $devices.PSObject.Properties | Where-Object { $_.Name -eq $NameArg }
        if (-not $entry) {
            $known = ($devices.PSObject.Properties.Name) -join ', '
            throw "Unknown device name '$NameArg'. Known: $known"
        }
        return ([string]$entry.Value).ToUpper().Replace('-', ':')
    }
    throw 'Specify -Mac <address> or -Name <alias>.'
}

# ------------------------------------------------------------- transport ---

$script:Cookies = New-Object System.Net.CookieContainer

function Invoke-RouterRpc {
    # Sends one JSON-RPC call. Performs the 401 challenge/response dance on
    # every call, so each request gets a fresh nonce and nc is always 1.
    param([hashtable]$Payload)

    $cred = Get-StoredCredential
    $pass = $cred.GetNetworkCredential().Password
    $body = $Payload | ConvertTo-Json -Depth 25 -Compress

    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.CookieContainer   = $script:Cookies
    $handler.UseCookies        = $true
    $handler.AllowAutoRedirect = $false
    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(20)

    try {
        # --- attempt 1: unauthenticated, expect 401 + challenge -------------
        $content = New-Object System.Net.Http.StringContent($body, [System.Text.Encoding]::UTF8, 'application/json')
        $resp    = $client.PostAsync("$BaseUrl$Endpoint", $content).GetAwaiter().GetResult()

        if ([int]$resp.StatusCode -ne 401) {
            $text = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            return ($text | ConvertFrom-Json)
        }

        $challenge = $null
        $hdr = $null
        if ($resp.Headers.TryGetValues('Anweb-Authenticate', [ref]$hdr)) { $challenge = @($hdr)[0] }
        if (-not $challenge) { throw 'Router did not return an Anweb-Authenticate challenge.' }

        $realm = ([regex]'realm="([^"]+)"').Match($challenge).Groups[1].Value
        $nonce = ([regex]'nonce="([^"]+)"').Match($challenge).Groups[1].Value
        $qop   = ([regex]'qop="?([a-zA-Z]+)"?').Match($challenge).Groups[1].Value
        if (-not $qop) { $qop = 'auth' }

        # --- build the digest response -------------------------------------
        $nc     = '00000001'
        $cnonce = New-Cnonce
        $ha1    = Get-Md5Hex "$($cred.UserName):${realm}:$pass"
        $ha2    = Get-Md5Hex "POST:$Endpoint"
        $rspVal = Get-Md5Hex "${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}"

        $userEsc = [uri]::EscapeDataString($cred.UserName)
        $fmt = 'Digest username="{0}", realm="{1}", nonce="{2}", uri="{3}", response="{4}", qop={5}, nc={6}, cnonce="{7}"'
        $authHeader = $fmt -f $userEsc, $realm, $nonce, $Endpoint, $rspVal, $qop, $nc, $cnonce

        # --- attempt 2: authenticated --------------------------------------
        $content2 = New-Object System.Net.Http.StringContent($body, [System.Text.Encoding]::UTF8, 'application/json')
        $req = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Post, "$BaseUrl$Endpoint")
        $req.Content = $content2
        # The web UI reads the challenge from "anweb-authenticate" but sends the
        # response back in the standard Authorization header, plus a marker that
        # this is a retry after a 401.
        $req.Headers.TryAddWithoutValidation('Authorization', $authHeader) | Out-Null
        $req.Headers.TryAddWithoutValidation('anweb-repeat-request', 'true') | Out-Null
        $resp2 = $client.SendAsync($req).GetAwaiter().GetResult()
        $text2 = $resp2.Content.ReadAsStringAsync().GetAwaiter().GetResult()

        if ([int]$resp2.StatusCode -eq 401) {
            $remain = $null
            $left   = 'unknown'
            if ($resp2.Headers.TryGetValues('Anweb-Auth-Try-Count-Remain', [ref]$remain)) { $left = @($remain)[0] }
            throw ("Authentication rejected by the router (attempts left before a temporary ban: $left). " +
                   "Most likely the stored password is wrong -- delete $CredFile and run 'setup' again.")
        }
        if (-not $text2) { throw "Empty response from router (HTTP $([int]$resp2.StatusCode))." }

        return ($text2 | ConvertFrom-Json)
    }
    finally {
        $client.Dispose()
    }
}

function Read-MacFilter {
    $r = Invoke-RouterRpc @{ jsonrpc = '2.0'; method = 'read'; params = @{ id = $CONFIG_ID }; id = 1 }
    if ($r.error) { throw "read failed: $($r.error | ConvertTo-Json -Compress)" }
    $mf = $r.result.data.macfilter
    if ($null -eq $mf) { throw 'Response contained no macfilter section. Run "dump" and inspect the output.' }
    return @($mf)
}

function Write-MacRule {
    param($Rule, [int]$Pos)
    $r = Invoke-RouterRpc @{
        jsonrpc = '2.0'
        method  = 'write'
        params  = @{ id = $CONFIG_ID; pos = $Pos; data = $Rule; save = $true }
        id      = 2
    }
    if ($r.error) { throw "write failed: $($r.error | ConvertTo-Json -Compress)" }
    return $r
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

function Get-LocalMacs {
    $macs = @()
    try {
        $macs = @(Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction Stop |
                  Where-Object { $_.MACAddress } |
                  ForEach-Object { $_.MACAddress.ToUpper() })
    } catch { }
    return $macs
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
        $active = 'off'
        if ($r.state) { $active = 'ON ' }
        $verb = 'allow'
        if ($r.enable -eq 'DROP') { $verb = 'BLOCK' }
        Write-Host ("  [{0}] {1,-18} {2}" -f $active, $r.mac, $verb)
    }
}

function Set-Block {
    param([string]$Target, [bool]$Blocked)

    if ($Blocked -and -not $Force) {
        if ((Get-LocalMacs) -contains $Target) {
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

switch ($Action) {

    'setup' {
        Get-StoredCredential | Out-Null
        if (-not (Test-Path $DevFile)) {
            @{ example = 'AA:BB:CC:DD:EE:01' } | ConvertTo-Json | Set-Content -Path $DevFile -Encoding UTF8
        }
        Write-Host ''
        Write-Host "Device aliases file: $DevFile"
        Write-Host 'Edit it to map friendly names to MAC addresses, e.g.'
        Write-Host '  { "tv": "AA:BB:CC:DD:EE:01", "kids": "AA:BB:CC:DD:EE:FF" }'
        Write-Host ''
        Write-Host 'Then check the connection with:  .\dlink-macfilter.ps1 status'
    }

    'dump' {
        $r = Invoke-RouterRpc @{ jsonrpc = '2.0'; method = 'read'; params = @{ id = $CONFIG_ID }; id = 1 }
        $r | ConvertTo-Json -Depth 25
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
