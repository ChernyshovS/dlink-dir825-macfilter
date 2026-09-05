<#
.SYNOPSIS
    Окно со списком блокировок на роутере.

.DESCRIPTION
    Показывает, какие устройства сейчас заблокированы, а какие разрешены.
    Данные берёт у dlink-macfilter.ps1 (действие dump), имена устройств —
    из devices.json.

    Ничего не меняет, только читает.

.EXAMPLE
    .\show-status.ps1
    .\show-status.ps1 -Text
#>
[CmdletBinding()]
param(
    # Вывести список в консоль вместо окна.
    [switch]$Text,

    [string]$Router = '192.168.0.1',
    [string]$User   = 'admin'
)

$ErrorActionPreference = 'Stop'

$MainScript = Join-Path $PSScriptRoot 'dlink-macfilter.ps1'
$DevFile    = Join-Path $PSScriptRoot 'devices.json'

if (-not (Test-Path $MainScript)) { throw "Рядом со скриптом не найден dlink-macfilter.ps1 ($PSScriptRoot)." }

# ------------------------------------------------------------------ данные ---

function Get-BlockState {
    <# Возвращает объект: Policy (текст политики по умолчанию) и Rows (список строк). #>

    $raw = & $MainScript dump -Router $Router -User $User | Out-String
    $obj = $raw | ConvertFrom-Json

    if ($obj.error) { throw "Роутер вернул ошибку: $($obj.error | ConvertTo-Json -Compress)" }

    $filter = @($obj.result.data.macfilter)

    # Политика по умолчанию — нулевой элемент с mac = null
    $base = $filter | Where-Object { $null -eq $_.mac } | Select-Object -First 1
    if ($base -and $base.state) {
        $policy = 'Запрещать всё, кроме исключений (белый список)'
    } elseif ($base) {
        $policy = 'Разрешать всё, кроме исключений (чёрный список)'
    } else {
        $policy = 'Разрешать всё — фильтр ещё не настроен'
    }

    # Имена устройств
    $aliases = @{}
    if (Test-Path $DevFile) {
        $devices = Get-Content $DevFile -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($p in $devices.PSObject.Properties) {
            $aliases[([string]$p.Value).ToUpper().Replace('-', ':')] = $p.Name
        }
    }

    $rows = @()
    $seen = @{}

    # Устройства, для которых на роутере есть правило
    foreach ($r in $filter) {
        if ($null -eq $r.mac) { continue }
        $mac = ([string]$r.mac).ToUpper()
        $seen[$mac] = $true

        $name = '—'
        if ($aliases.ContainsKey($mac)) { $name = $aliases[$mac] }

        $blocked = ([bool]$r.state) -and ($r.enable -eq 'DROP')
        if ($blocked) { $state = 'Заблокировано' } else { $state = 'Разрешено (правило выключено)' }

        $rows += [pscustomobject]@{ Name = $name; Mac = $mac; State = $state; Blocked = $blocked }
    }

    # Устройства из devices.json, для которых правила нет вовсе
    foreach ($mac in $aliases.Keys) {
        if ($seen.ContainsKey($mac)) { continue }
        $rows += [pscustomobject]@{
            Name = $aliases[$mac]; Mac = $mac; State = 'Разрешено (правила нет)'; Blocked = $false
        }
    }

    # Сначала заблокированные, потом по имени
    $rows = $rows | Sort-Object @{ Expression = 'Blocked'; Descending = $true }, Name

    return [pscustomobject]@{ Policy = $policy; Rows = @($rows) }
}

# ----------------------------------------------------------- вывод в текст ---

if ($Text) {
    $data = Get-BlockState
    Write-Host ''
    Write-Host "Политика по умолчанию: $($data.Policy)"
    Write-Host ''
    if ($data.Rows.Count -eq 0) {
        Write-Host '  Устройств нет'
    } else {
        foreach ($row in $data.Rows) {
            if ($row.Blocked) { $color = 'Red' } else { $color = 'Green' }
            Write-Host ("  {0,-12} {1,-19} " -f $row.Name, $row.Mac) -NoNewline
            Write-Host $row.State -ForegroundColor $color
        }
    }
    Write-Host ''
    Write-Host "Обновлено: $(Get-Date -Format 'HH:mm:ss')"
    return
}

# ------------------------------------------------------------------- окно ---

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$form = New-Object System.Windows.Forms.Form
$form.Text          = 'Блокировки на роутере'
$form.Size          = New-Object System.Drawing.Size(580, 420)
$form.StartPosition = 'CenterScreen'
$form.Font          = New-Object System.Drawing.Font('Segoe UI', 9.5)
$form.MinimumSize   = New-Object System.Drawing.Size(460, 300)

$lblPolicy = New-Object System.Windows.Forms.Label
$lblPolicy.Location = New-Object System.Drawing.Point(14, 12)
$lblPolicy.Size     = New-Object System.Drawing.Size(540, 22)
$lblPolicy.Anchor   = 'Top,Left,Right'
$form.Controls.Add($lblPolicy)

$list = New-Object System.Windows.Forms.ListView
$list.Location      = New-Object System.Drawing.Point(14, 40)
$list.Size          = New-Object System.Drawing.Size(540, 290)
$list.Anchor        = 'Top,Left,Right,Bottom'
$list.View          = 'Details'
$list.FullRowSelect = $true
$list.GridLines     = $true
$list.HeaderStyle   = 'Nonclickable'
$list.Columns.Add('Устройство', 120)      | Out-Null
$list.Columns.Add('MAC-адрес', 165)       | Out-Null
$list.Columns.Add('Состояние', 240)       | Out-Null
$form.Controls.Add($list)

$lblTime = New-Object System.Windows.Forms.Label
$lblTime.Location  = New-Object System.Drawing.Point(14, 344)
$lblTime.Size      = New-Object System.Drawing.Size(240, 22)
$lblTime.Anchor    = 'Bottom,Left'
$lblTime.ForeColor = [System.Drawing.Color]::Gray
$form.Controls.Add($lblTime)

$btnRefresh = New-Object System.Windows.Forms.Button
$btnRefresh.Text     = 'Обновить'
$btnRefresh.Location = New-Object System.Drawing.Point(374, 340)
$btnRefresh.Size     = New-Object System.Drawing.Size(85, 28)
$btnRefresh.Anchor   = 'Bottom,Right'
$form.Controls.Add($btnRefresh)

$btnClose = New-Object System.Windows.Forms.Button
$btnClose.Text     = 'Закрыть'
$btnClose.Location = New-Object System.Drawing.Point(469, 340)
$btnClose.Size     = New-Object System.Drawing.Size(85, 28)
$btnClose.Anchor   = 'Bottom,Right'
$btnClose.Add_Click({ $form.Close() })
$form.Controls.Add($btnClose)

$colorBlocked = [System.Drawing.Color]::FromArgb(178, 34, 34)
$colorAllowed = [System.Drawing.Color]::FromArgb(34, 120, 34)

function Update-View {
    $form.Cursor = 'WaitCursor'
    $btnRefresh.Enabled = $false
    $list.Items.Clear()
    try {
        $data = Get-BlockState
        $lblPolicy.Text = "Политика по умолчанию: $($data.Policy)"

        foreach ($row in $data.Rows) {
            $item = New-Object System.Windows.Forms.ListViewItem($row.Name)
            $item.SubItems.Add($row.Mac)   | Out-Null
            if ($row.Blocked) {
                $item.SubItems.Add('● ' + $row.State) | Out-Null
                $item.ForeColor = $colorBlocked
                $item.Font = New-Object System.Drawing.Font($form.Font, [System.Drawing.FontStyle]::Bold)
            } else {
                $item.SubItems.Add('● ' + $row.State) | Out-Null
                $item.ForeColor = $colorAllowed
            }
            $list.Items.Add($item) | Out-Null
        }

        if ($data.Rows.Count -eq 0) {
            $item = New-Object System.Windows.Forms.ListViewItem('—')
            $item.SubItems.Add('') | Out-Null
            $item.SubItems.Add('Устройств нет') | Out-Null
            $list.Items.Add($item) | Out-Null
        }

        $lblTime.Text = "Обновлено: $(Get-Date -Format 'HH:mm:ss')"
    }
    catch {
        $lblPolicy.Text = 'Не удалось получить данные'
        $lblTime.Text   = ''
        [System.Windows.Forms.MessageBox]::Show(
            $_.Exception.Message, 'Ошибка связи с роутером',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
    }
    finally {
        $btnRefresh.Enabled = $true
        $form.Cursor = 'Default'
    }
}

$btnRefresh.Add_Click({ Update-View })
$form.Add_Shown({ $form.Activate(); Update-View })

[void]$form.ShowDialog()
