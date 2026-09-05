<#
.SYNOPSIS
    Creates desktop shortcuts for every device listed in devices.json.

.DESCRIPTION
    For each alias in devices.json (kept next to these scripts) this creates
    one "toggle" shortcut. Double-click blocks the device; double-click
    again lets it back on the network.

    Use -Mode block or -Mode unblock to make one-way shortcuts instead,
    and -Folder to put them somewhere other than the Desktop.

.EXAMPLE
    .\make-shortcuts.ps1
    .\make-shortcuts.ps1 -Mode block -Folder "$env:USERPROFILE\Desktop\Router"
#>
[CmdletBinding()]
param(
    [ValidateSet('toggle', 'block', 'unblock')]
    [string]$Mode = 'toggle',

    [string]$Folder = [Environment]::GetFolderPath('Desktop')
)

$ErrorActionPreference = 'Stop'

$ScriptPath = Join-Path $PSScriptRoot 'dlink-macfilter.ps1'
if (-not (Test-Path $ScriptPath)) { throw "dlink-macfilter.ps1 not found next to this script ($PSScriptRoot)." }

$DevFile = Join-Path $PSScriptRoot 'devices.json'
if (-not (Test-Path $DevFile)) { throw "devices.json not found in $PSScriptRoot. Run: .\dlink-macfilter.ps1 setup" }

$devices = Get-Content $DevFile -Raw | ConvertFrom-Json
$names   = @($devices.PSObject.Properties.Name)
if ($names.Count -eq 0) { throw "No devices defined in $DevFile" }

if (-not (Test-Path $Folder)) { New-Item -ItemType Directory -Path $Folder | Out-Null }

# Verb used in the shortcut label
$label = @{ toggle = 'Toggle'; block = 'Block'; unblock = 'Allow' }[$Mode]

$shell = New-Object -ComObject WScript.Shell
foreach ($name in $names) {
    $lnkPath = Join-Path $Folder "$label $name.lnk"
    $lnk = $shell.CreateShortcut($lnkPath)
    $lnk.TargetPath       = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $lnk.Arguments        = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" $Mode -Name $name"
    $lnk.WorkingDirectory = $PSScriptRoot
    $lnk.Description      = "$label network access for '$name' on the router"
    $lnk.IconLocation     = "$env:SystemRoot\System32\shell32.dll,48"
    $lnk.Save()
    Write-Host "Created: $lnkPath" -ForegroundColor Green
}

# One extra shortcut that only shows what is currently blocked.
# -WindowStyle Hidden keeps the console out of the way: only the window shows.
$StatusScript = Join-Path $PSScriptRoot 'show-status.ps1'
if (Test-Path $StatusScript) {
    $statusLnk = Join-Path $Folder 'Status.lnk'
    $lnk = $shell.CreateShortcut($statusLnk)
    $lnk.TargetPath       = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $lnk.Arguments        = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$StatusScript`""
    $lnk.WorkingDirectory = $PSScriptRoot
    $lnk.Description      = 'Show which devices are currently blocked on the router'
    $lnk.IconLocation     = "$env:SystemRoot\System32\shell32.dll,23"
    $lnk.Save()
    Write-Host "Created: $statusLnk" -ForegroundColor Green
} else {
    Write-Host 'show-status.ps1 not found next to this script; status shortcut skipped.' -ForegroundColor DarkYellow
}

Write-Host ''
Write-Host "Done. $($names.Count) shortcut(s) in $Folder"
Write-Host 'The console window closes on its own; add -NoExit to Arguments if you want to read the output.'
