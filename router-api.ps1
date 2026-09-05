<#
    Shared low-level access to the router's JSON-RPC API.

    Dot-source it, call Initialize-RouterApi once, then use
    Read-RouterConfig / Write-RouterConfig.

        . (Join-Path $PSScriptRoot 'router-api.ps1')
        Initialize-RouterApi -Router '192.168.0.1' -User 'admin' -CredFile '...\cred.xml'

    Authentication is HTTP Digest MD5 (qop=auth): the challenge arrives in the
    non-standard "anweb-authenticate" response header, the answer goes back in
    the ordinary Authorization header plus "anweb-repeat-request: true".
#>

Add-Type -AssemblyName System.Net.Http

$script:RA_Router   = '192.168.0.1'
$script:RA_User     = 'admin'
$script:RA_CredFile = $null
$script:RA_Endpoint = '/jsonrpc'

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

function Invoke-RouterRpc {
    param([Parameter(Mandatory = $true)][hashtable]$Payload)

    $cred = Get-RouterCredential
    $pass = $cred.GetNetworkCredential().Password
    $body = $Payload | ConvertTo-Json -Depth 25 -Compress
    $url  = "http://$($script:RA_Router)$($script:RA_Endpoint)"

    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.CookieContainer   = New-Object System.Net.CookieContainer
    $handler.UseCookies        = $true
    $handler.AllowAutoRedirect = $false
    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(20)

    try {
        $c1 = New-Object System.Net.Http.StringContent($body, [System.Text.Encoding]::UTF8, 'application/json')
        $r1 = $client.PostAsync($url, $c1).GetAwaiter().GetResult()

        if ([int]$r1.StatusCode -ne 401) {
            return ($r1.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json)
        }

        $hdr = $null
        if (-not $r1.Headers.TryGetValues('Anweb-Authenticate', [ref]$hdr)) {
            throw 'Router did not return an Anweb-Authenticate challenge.'
        }
        $challenge = @($hdr)[0]

        $realm = ([regex]'realm="([^"]+)"').Match($challenge).Groups[1].Value
        $nonce = ([regex]'nonce="([^"]+)"').Match($challenge).Groups[1].Value
        $qop   = ([regex]'qop="?([a-zA-Z]+)"?').Match($challenge).Groups[1].Value
        if (-not $qop) { $qop = 'auth' }

        $nc     = '00000001'
        $chars  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
        $cnonce = -join (1..16 | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })

        $ha1    = Get-RouterMd5Hex "$($cred.UserName):${realm}:$pass"
        $ha2    = Get-RouterMd5Hex "POST:$($script:RA_Endpoint)"
        $rspVal = Get-RouterMd5Hex "${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}"

        $fmt = 'Digest username="{0}", realm="{1}", nonce="{2}", uri="{3}", response="{4}", qop={5}, nc={6}, cnonce="{7}"'
        $authHeader = $fmt -f [uri]::EscapeDataString($cred.UserName), $realm, $nonce,
                              $script:RA_Endpoint, $rspVal, $qop, $nc, $cnonce

        $c2  = New-Object System.Net.Http.StringContent($body, [System.Text.Encoding]::UTF8, 'application/json')
        $req = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Post, $url)
        $req.Content = $c2
        $req.Headers.TryAddWithoutValidation('Authorization', $authHeader) | Out-Null
        $req.Headers.TryAddWithoutValidation('anweb-repeat-request', 'true') | Out-Null
        $r2 = $client.SendAsync($req).GetAwaiter().GetResult()
        $text = $r2.Content.ReadAsStringAsync().GetAwaiter().GetResult()

        if ([int]$r2.StatusCode -eq 401) {
            $remain = $null
            $left = 'unknown'
            if ($r2.Headers.TryGetValues('Anweb-Auth-Try-Count-Remain', [ref]$remain)) { $left = @($remain)[0] }
            throw ("Authentication rejected by the router (attempts left before a temporary ban: $left). " +
                   "Delete $($script:RA_CredFile) and run 'setup' again.")
        }
        if (-not $text) { throw "Empty response from router (HTTP $([int]$r2.StatusCode))." }

        return ($text | ConvertFrom-Json)
    }
    finally { $client.Dispose() }
}

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
    if ($r.error)          { throw "read $Id failed: $($r.error | ConvertTo-Json -Compress)" }
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
    if ($r.error)          { throw "write $Id failed: $($r.error | ConvertTo-Json -Compress)" }
    if ($r.result.status -ne 20) { throw "write $Id returned status $($r.result.status)" }
    return $r.result
}
