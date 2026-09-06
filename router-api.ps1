<#
    Shared low-level access to the router's HTTP API.

    Dot-source it, call Initialize-RouterApi once, then use the wrappers:

        . (Join-Path $PSScriptRoot 'router-api.ps1')
        Initialize-RouterApi -Router '192.168.0.1' -User 'admin' -CredFile '...\cred.xml'

    Two endpoints are covered.

      POST /jsonrpc   reads and writes the stored configuration
      GET  /devinfo   reads live status: clients, leases, wireless links

    Authentication is HTTP Digest MD5 (qop=auth) for both, with one twist:
    the challenge arrives in the non-standard "anweb-authenticate" response
    header, while the answer goes back in the ordinary Authorization header
    plus "anweb-repeat-request: true".
#>

Add-Type -AssemblyName System.Net.Http

$script:RA_Router   = '192.168.0.1'
$script:RA_User     = 'admin'
$script:RA_CredFile = $null
$script:RA_Endpoint = '/jsonrpc'
$script:RA_DevInfo  = '/devinfo'

function Initialize-RouterApi {
    param(
        [string]$Router   = '192.168.0.1',
        [string]$User     = 'admin',
        [Parameter(Mandatory = $true)][string]$CredFile
    )
    $script:RA_Router   = $Router
    $script:RA_User     = $User
    $script:RA_CredFile = $CredFile
}

function Get-RouterCredential {
    if (-not $script:RA_CredFile) { throw 'Initialize-RouterApi has not been called.' }
    if (-not (Test-Path $script:RA_CredFile)) {
        throw "Router password not stored yet ($($script:RA_CredFile)). Run: .\dlink-macfilter.ps1 setup"
    }
    Import-Clixml -Path $script:RA_CredFile
}

function Get-RouterMd5Hex([string]$Text) {
    $md5   = [System.Security.Cryptography.MD5]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    -join ($md5.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })
}

function ConvertTo-RouterMac([string]$Mac) {
    <#  One spelling of a MAC address everywhere: upper case, colon
        separated. The router itself is inconsistent -- /devinfo area 64
        answers in upper case, area 34 and the config calls in lower. #>
    return ([string]$Mac).Trim().ToUpper().Replace('-', ':')
}

function Get-LocalMacAddresses {
    <#  Addresses of this computer's own adapters, so callers can refuse to
        block or de-whitelist the machine they are being run from. Lives here
        because every script in the folder needs the same guard. #>
    try {
        return @(Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction Stop |
                 Where-Object { $_.MACAddress } |
                 ForEach-Object { ConvertTo-RouterMac $_.MACAddress })
    } catch { return @() }
}

# --------------------------------------------------------------- transport ---

function New-RouterHttpClient {
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.CookieContainer   = New-Object System.Net.CookieContainer
    $handler.UseCookies        = $true
    $handler.AllowAutoRedirect = $false
    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(20)
    return $client
}

function Get-RouterChallenge($Response) {
    $hdr = $null
    if (-not $Response.Headers.TryGetValues('Anweb-Authenticate', [ref]$hdr)) {
        throw 'Router did not return an Anweb-Authenticate challenge.'
    }
    return @($hdr)[0]
}

function New-RouterDigestHeader {
    <#  Path is the bare path, without a query string: the router computes
        HA2 over "METHOD:/devinfo", not over the full request target. #>
    param(
        [Parameter(Mandatory = $true)][string]$Challenge,
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Cred
    )

    $realm = ([regex]'realm="([^"]+)"').Match($Challenge).Groups[1].Value
    $nonce = ([regex]'nonce="([^"]+)"').Match($Challenge).Groups[1].Value
    $qop   = ([regex]'qop="?([a-zA-Z]+)"?').Match($Challenge).Groups[1].Value
    if (-not $qop) { $qop = 'auth' }

    $nc     = '00000001'
    $chars  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    $cnonce = -join (1..16 | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })

    $pass   = $Cred.GetNetworkCredential().Password
    $ha1    = Get-RouterMd5Hex "$($Cred.UserName):${realm}:$pass"
    $ha2    = Get-RouterMd5Hex "${Method}:${Path}"
    $rspVal = Get-RouterMd5Hex "${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}"

    $fmt = 'Digest username="{0}", realm="{1}", nonce="{2}", uri="{3}", response="{4}", qop={5}, nc={6}, cnonce="{7}"'
    return ($fmt -f [uri]::EscapeDataString($Cred.UserName), $realm, $nonce, $Path, $rspVal, $qop, $nc, $cnonce)
}

function Assert-RouterAuthorized($Response) {
    <#  A second 401 means the password is wrong. The router bans further
        attempts after five, so say how many are left rather than retrying. #>
    if ([int]$Response.StatusCode -ne 401) { return }
    $remain = $null
    $left = 'unknown'
    if ($Response.Headers.TryGetValues('Anweb-Auth-Try-Count-Remain', [ref]$remain)) { $left = @($remain)[0] }
    throw ("Authentication rejected by the router (attempts left before a temporary ban: $left). " +
           "Delete $($script:RA_CredFile) and run 'setup' again.")
}

function Invoke-RouterRpc {
    param([Parameter(Mandatory = $true)][hashtable]$Payload)

    $cred = Get-RouterCredential
    $body = $Payload | ConvertTo-Json -Depth 25 -Compress
    $url  = "http://$($script:RA_Router)$($script:RA_Endpoint)"

    $client = New-RouterHttpClient
    try {
        $c1 = New-Object System.Net.Http.StringContent($body, [System.Text.Encoding]::UTF8, 'application/json')
        $r1 = $client.PostAsync($url, $c1).GetAwaiter().GetResult()

        if ([int]$r1.StatusCode -ne 401) {
            return ($r1.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json)
        }

        $auth = New-RouterDigestHeader -Challenge (Get-RouterChallenge $r1) `
                                       -Method 'POST' -Path $script:RA_Endpoint -Cred $cred

        $c2  = New-Object System.Net.Http.StringContent($body, [System.Text.Encoding]::UTF8, 'application/json')
        $req = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Post, $url)
        $req.Content = $c2
        $req.Headers.TryAddWithoutValidation('Authorization', $auth) | Out-Null
        $req.Headers.TryAddWithoutValidation('anweb-repeat-request', 'true') | Out-Null
        $r2 = $client.SendAsync($req).GetAwaiter().GetResult()

        Assert-RouterAuthorized $r2
        $text = $r2.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if (-not $text) { throw "Empty response from router (HTTP $([int]$r2.StatusCode))." }

        return ($text | ConvertFrom-Json)
    }
    finally { $client.Dispose() }
}

function Get-RouterDevInfo {
    <#  Live status, read-only. Several areas can be fetched in one request;
        the result is an object with one property per area name.

            $info = Get-RouterDevInfo -Area '187','34','64'
            $info.'34'    # DHCP leases

        Useful areas: 187 clients, 34 DHCP leases, 64 wireless links,
        client (the caller itself), version (model and firmware).

        Unlike the config calls this touches nothing, so it needs no
        Save-RouterConfig afterwards. #>
    param([Parameter(Mandatory = $true)][string[]]$Area)

    $cred = Get-RouterCredential
    $path = $script:RA_DevInfo
    $url  = "http://$($script:RA_Router)$path" + '?area=' + ($Area -join '|') + '&need_auth=1'

    $client = New-RouterHttpClient
    try {
        $r1 = $client.GetAsync($url).GetAwaiter().GetResult()
        if ([int]$r1.StatusCode -eq 200) {
            return (($r1.Content.ReadAsStringAsync().GetAwaiter().GetResult()) | ConvertFrom-Json).result
        }
        if ([int]$r1.StatusCode -ne 401) { throw "devinfo returned HTTP $([int]$r1.StatusCode)." }

        $auth = New-RouterDigestHeader -Challenge (Get-RouterChallenge $r1) `
                                       -Method 'GET' -Path $path -Cred $cred

        $req = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, $url)
        $req.Headers.TryAddWithoutValidation('Authorization', $auth) | Out-Null
        $req.Headers.TryAddWithoutValidation('anweb-repeat-request', 'true') | Out-Null
        $r2 = $client.SendAsync($req).GetAwaiter().GetResult()

        Assert-RouterAuthorized $r2
        $text = $r2.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if (-not $text) { throw "Empty devinfo response (HTTP $([int]$r2.StatusCode))." }

        return ($text | ConvertFrom-Json).result
    }
    finally { $client.Dispose() }
}

# ------------------------------------------------------------ config calls ---

function Save-RouterConfig {
    <#  Commits the running configuration to flash (cmd id 20).

        Call it once at the end of an operation. Without it the router keeps
        a "configuration changed" flag and asks the user to save by hand,
        even when the only pending change is a transient cursor value. #>
    $r = Invoke-RouterRpc @{ jsonrpc = '2.0'; method = 'cmd'; params = @{ id = 20 }; id = 3 }
    if ($r.error) { throw "save failed: $($r.error | ConvertTo-Json -Compress)" }
    return $r.result
}

function Read-RouterConfig {
    param([Parameter(Mandatory = $true)][int]$Id)

    $r = Invoke-RouterRpc @{ jsonrpc = '2.0'; method = 'read'; params = @{ id = $Id }; id = 1 }
    if ($r.error)                { throw "read $Id failed: $($r.error | ConvertTo-Json -Compress)" }
    if ($r.result.status -ne 20) { throw "read $Id returned status $($r.result.status)" }
    return $r.result.data
}

function Write-RouterConfig {
    <#  Pos:  -1 appends a new list entry, a number replaces an existing one,
              omit it for a plain field update.
        Save: commit to flash. Pass $false for transient values such as the
              mbssid cursor, so the flash is not written on every read. #>
    param(
        [Parameter(Mandatory = $true)][int]$Id,
        [Parameter(Mandatory = $true)]$Data,
        [int]$Pos,
        [bool]$Save = $true
    )

    $params = @{ id = $Id; data = $Data; save = $Save }
    if ($PSBoundParameters.ContainsKey('Pos')) { $params['pos'] = $Pos }

    $r = Invoke-RouterRpc @{ jsonrpc = '2.0'; method = 'write'; params = $params; id = 2 }
    if ($r.error)                { throw "write $Id failed: $($r.error | ConvertTo-Json -Compress)" }
    if ($r.result.status -ne 20) { throw "write $Id returned status $($r.result.status)" }
    return $r.result
}

function Remove-RouterConfig {
    <#  Deletes one entry from a list-shaped configuration. Data carries the
        same container a matching Write-RouterConfig call would use, Pos is
        the entry's own key inside that container.

        Removing shifts the keys of everything after it, so when deleting
        several entries, work from the highest position downwards. #>
    param(
        [Parameter(Mandatory = $true)][int]$Id,
        [Parameter(Mandatory = $true)]$Data,
        [Parameter(Mandatory = $true)][int]$Pos,
        [bool]$Save = $true
    )

    $params = @{ id = $Id; data = $Data; pos = $Pos; save = $Save }
    $r = Invoke-RouterRpc @{ jsonrpc = '2.0'; method = 'remove'; params = $params; id = 4 }
    if ($r.error)                { throw "remove $Id failed: $($r.error | ConvertTo-Json -Compress)" }
    if ($r.result.status -ne 20) { throw "remove $Id returned status $($r.result.status)" }
    return $r.result
}
