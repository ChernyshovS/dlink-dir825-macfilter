<#
.SYNOPSIS
    Creates desktop shortcuts for every device listed in devices.json.

.DESCRIPTION
    For each alias in devices.json (kept next to these scripts) this creates
    one "toggle" shortcut. Double-click blocks the device; double-click
    again lets it back on the network.

    Four more shortcuts are created alongside them: Devices (pick who to
    block or whitelist), Status (read-only overview), Whitelist ON and
    Whitelist OFF.

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

# An empty device list is not an error: the standalone shortcuts below are
# still worth creating, and pick-devices.ps1 is how the list gets filled.
if ($names.Count -eq 0) {
    Write-Host "No devices defined in $DevFile yet; per-device shortcuts skipped." -ForegroundColor DarkYellow
}

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

# Picker window: shows what the router currently sees and lets the user tick
# devices into the block list and the Wi-Fi whitelist. This is how devices.json
# gets filled in the first place, so the shortcut is worth having even when
# there are no per-device shortcuts yet.
$PickerScript = Join-Path $PSScriptRoot 'pick-devices.ps1'
if (Test-Path $PickerScript) {
    $pickLnk = Join-Path $Folder 'Devices.lnk'
    $lnk = $shell.CreateShortcut($pickLnk)
    $lnk.TargetPath       = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $lnk.Arguments        = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$PickerScript`""
    $lnk.WorkingDirectory = $PSScriptRoot
    $lnk.Description      = 'Pick devices to block or to keep on the Wi-Fi whitelist'
    $lnk.IconLocation     = "$env:SystemRoot\System32\shell32.dll,18"
    $lnk.Save()
    Write-Host "Created: $pickLnk" -ForegroundColor Green
} else {
    Write-Host 'pick-devices.ps1 not found next to this script; picker shortcut skipped.' -ForegroundColor DarkYellow
}

# Wi-Fi whitelist: two explicit shortcuts rather than one toggle, so it is
# always obvious which way the switch goes. Turning it ON asks for confirmation
# in a dialog of its own (the console is hidden, so a console prompt would be
# invisible); turning it OFF is the safe direction and just reports the result.
$WhitelistScript = Join-Path $PSScriptRoot 'wifi-whitelist.ps1'
if (Test-Path $WhitelistScript) {
    $wlShortcuts = @(
        @{ File = 'Whitelist ON.lnk';  Arg = 'on';  Icon = 28; Desc = 'Leave Wi-Fi access to whitelisted devices only' },
        @{ File = 'Whitelist OFF.lnk'; Arg = 'off'; Icon = 29; Desc = 'Open Wi-Fi back to every device' }
    )
    foreach ($s in $wlShortcuts) {
        $p = Join-Path $Folder $s.File
        $lnk = $shell.CreateShortcut($p)
        $lnk.TargetPath       = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $lnk.Arguments        = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$WhitelistScript`" $($s.Arg)"
        $lnk.WorkingDirectory = $PSScriptRoot
        $lnk.Description      = $s.Desc
        $lnk.IconLocation     = "$env:SystemRoot\System32\shell32.dll,$($s.Icon)"
        $lnk.Save()
        Write-Host "Created: $p" -ForegroundColor Green
    }
} else {
    Write-Host 'wifi-whitelist.ps1 not found next to this script; whitelist shortcuts skipped.' -ForegroundColor DarkYellow
}

Write-Host ''
Write-Host "Done. $($names.Count) shortcut(s) in $Folder"
Write-Host 'The console window closes on its own; add -NoExit to Arguments if you want to read the output.'
