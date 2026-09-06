<#
.SYNOPSIS
    Окно выбора устройств: кого заблокировать и кого держать в белом списке.

.DESCRIPTION
    Показывает устройства, которые роутер видит сейчас или видел за последние
    сутки, и позволяет отметить галочками, кого блокировать и кого пускать
    по белому списку Wi-Fi. Имя можно исправить прямо в таблице — оно станет
    ключом в devices.json и именем ярлыка.

    Список собирается из четырёх источников: клиенты роутера, аренды DHCP,
    беспроводные соединения и текущие правила фильтра. К ним добавляются
    устройства из devices.json и whitelist.json, даже если сейчас их нет
    в сети, — иначе снять с них галочку было бы невозможно.

    Пока не нажата кнопка «Применить», не меняется ничего. Перед изменениями
    показывается список того, что именно будет сделано.

.EXAMPLE
    .\pick-devices.ps1
    .\pick-devices.ps1 -Text
#>
[CmdletBinding()]
param(
    # Вывести список в консоль вместо окна. Ничего не меняет.
    [switch]$Text,

    [string]$Router = '192.168.0.1',
    [string]$User   = 'admin'
)

$ErrorActionPreference = 'Stop'

$MainScript      = Join-Path $PSScriptRoot 'dlink-macfilter.ps1'
$WhitelistScript = Join-Path $PSScriptRoot 'wifi-whitelist.ps1'
$CredFile        = Join-Path $PSScriptRoot 'cred.xml'
$DevFile         = Join-Path $PSScriptRoot 'devices.json'
$WhitelistFile   = Join-Path $PSScriptRoot 'whitelist.json'

if (-not (Test-Path $MainScript)) { throw "Рядом со скриптом не найден dlink-macfilter.ps1 ($PSScriptRoot)." }

. (Join-Path $PSScriptRoot 'router-api.ps1')
Initialize-RouterApi -Router $Router -User $User -CredFile $CredFile

$CFG_FIREWALL = 74   # MAC-фильтр межсетевого экрана: и Wi-Fi, и витая пара

# ------------------------------------------------------------------ данные ---

function Test-RandomMac([string]$Mac) {
    <#  Второй бит первого октета: единица означает локально назначенный
        адрес, то есть случайный. Такое устройство меняет адрес при
        переподключении, и правило, записанное на него, перестаёт работать. #>
    if ($Mac.Length -lt 2) { return $false }
    try { $first = [Convert]::ToInt32($Mac.Substring(0, 2), 16) } catch { return $false }
    return (($first -band 2) -ne 0)
}

function Get-SafeAlias([string]$Name) {
    <#  Имя становится ключом devices.json и именем файла ярлыка, поэтому
        выкидываем всё, что Windows не пустит в имя файла. #>
    $clean = ([string]$Name) -replace '[\\/:\*\?"<>\|]', '-'
    $clean = $clean -replace '\s+', '-'
    $clean = $clean.Trim([char[]]@('-', ' ', '.'))
    if ($clean.Length -gt 24) { $clean = $clean.Substring(0, 24) }
    return $clean
}

function Get-Slot($Map, [string]$Mac) {
    $key = ConvertTo-RouterMac $Mac
    if (-not $Map.Contains($key)) {
        $Map[$key] = [pscustomobject]@{
            Mac         = $key
            Alias       = ''
            Hostname    = ''
            Ip          = ''
            Vendor      = ''
            Wireless    = $false
            Wired       = $false
            Band        = ''
            Online      = $false
            Blocked     = $false
            InDevices   = $false
            InWhitelist = $false
            WlBand      = 'both'
            Random      = (Test-RandomMac $key)
        }
    }
    return $Map[$key]
}

function Get-DeviceInventory {
    $map = [ordered]@{}

    $info = Get-RouterDevInfo -Area '187', '34', '64'

    # Аренды DHCP — самый широкий срез: всё, что подключалось за сутки.
    foreach ($l in @($info.'34')) {
        if (-not $l.MACAddress) { continue }
        $r = Get-Slot $map $l.MACAddress
        if ($l.hostname) { $r.Hostname = [string]$l.hostname }
        if ($l.ip)       { $r.Ip       = [string]$l.ip }
        if ($l.vendorid) { $r.Vendor   = [string]$l.vendorid }
    }

    # Клиенты: роутер отдаёт строку на каждый IP-адрес, а у устройства их
    # бывает под десяток из-за IPv6, поэтому сворачиваем по MAC.
    foreach ($c in @($info.'187')) {
        if (-not $c.mac) { continue }
        $r = Get-Slot $map $c.mac
        if ($c.hostname) { $r.Hostname = [string]$c.hostname }
        if ($c.ip -and ([string]$c.ip) -notmatch ':') { $r.Ip = [string]$c.ip }
        if ([string]$c.flags -match 'reachable') { $r.Online = $true }
        if ($c.name -eq 'WLAN') { $r.Wireless = $true }
        elseif ($c.name)        { $r.Wired    = $true }
    }

    # Беспроводные соединения — единственный надёжный признак того, что
    # устройство именно на Wi-Fi, и единственный источник диапазона.
    foreach ($w in @($info.'64')) {
        if (-not $w.mac) { continue }
        $r = Get-Slot $map $w.mac
        $r.Wireless = $true
        $r.Online   = $true
        if ($w.band)     { $r.Band     = [string]$w.band }
        if ($w.hostname) { $r.Hostname = [string]$w.hostname }
    }

    # Текущие блокировки.
    $fw = Read-RouterConfig -Id $CFG_FIREWALL
    foreach ($f in @($fw.macfilter)) {
        if ($null -eq $f.mac) { continue }
        $r = Get-Slot $map $f.mac
        $r.Blocked = ([bool]$f.state) -and ($f.enable -eq 'DROP')
    }

    # Имена из devices.json.
    if (Test-Path $DevFile) {
        $devices = Get-Content $DevFile -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($p in $devices.PSObject.Properties) {
            if (-not $p.Value) { continue }
            $r = Get-Slot $map $p.Value
            $r.Alias     = $p.Name
            $r.InDevices = $true
        }
    }

    # Белый список.
    if (Test-Path $WhitelistFile) {
        $wl = Get-Content $WhitelistFile -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($e in @($wl)) {
            if (-not $e.mac) { continue }
            $r = Get-Slot $map $e.mac
            $r.InWhitelist = $true
            if ($e.band) { $r.WlBand = [string]$e.band }
            if (-not $r.Alias -and $e.name) { $r.Alias = [string]$e.name }
        }
    }

    # Имя по умолчанию — из имени узла. Одинаковые разводим суффиксом:
    # у телефона с рандомизацией адресов несколько, а имя узла одно.
    $used = @{}
    foreach ($r in $map.Values) { if ($r.Alias) { $used[$r.Alias.ToLower()] = $true } }
    foreach ($r in $map.Values) {
        if ($r.Alias) { continue }
        $base = Get-SafeAlias $r.Hostname
        if (-not $base) { $base = 'dev-' + ($r.Mac -replace ':', '').Substring(6) }
        $candidate = $base
        $n = 2
        while ($used.ContainsKey($candidate.ToLower())) { $candidate = "$base-$n"; $n++ }
        $used[$candidate.ToLower()] = $true
        $r.Alias = $candidate
    }

    return @($map.Values |
             Sort-Object @{ Expression = 'Online';  Descending = $true },
                         @{ Expression = 'Blocked'; Descending = $true },
                         @{ Expression = 'Alias';   Descending = $false })
}

function Get-LinkText($Row) {
    if ($Row.Wireless) {
        if ($Row.Band) { return 'Wi-Fi ' + ($Row.Band -replace 'GHz', 'ГГц') }
        return 'Wi-Fi'
    }
    if ($Row.Wired) { return 'витая пара' }
    return '—'
}

function Get-StateText($Row) {
    if ($Row.Online) { return 'в сети' }
    return 'был в сети'
}

# ------------------------------------------------------------ запись файлов ---

function Save-DeviceAliases($Entries) {
    $obj = [ordered]@{}
    foreach ($e in $Entries) { $obj[$e.Alias] = $e.Mac }
    ($obj | ConvertTo-Json) | Set-Content -Path $DevFile -Encoding UTF8
}

function Save-Whitelist($Entries) {
    $list = @()
    foreach ($e in $Entries) {
        $list += [pscustomobject]@{ name = $e.Alias; mac = $e.Mac; band = $e.Band }
    }
    if ($list.Count -eq 0) {
        '[]' | Set-Content -Path $WhitelistFile -Encoding UTF8
        return
    }
    # -InputObject, а не конвейер: иначе список из одной записи превратится
    # в объект вместо массива, и wifi-whitelist.ps1 его не прочитает.
    (ConvertTo-Json -InputObject $list -Depth 5) | Set-Content -Path $WhitelistFile -Encoding UTF8
}

# ------------------------------------------------------------- вывод в текст ---

if ($Text) {
    $inv = Get-DeviceInventory
    Write-Host ''
    Write-Host ('{0,-20} {1,-19} {2,-14} {3,-11} {4,-16} {5}' -f `
                'Имя', 'MAC-адрес', 'Подключение', 'Состояние', 'IP-адрес', 'Списки')
    Write-Host ('-' * 105)
    foreach ($r in $inv) {
        $marks = @()
        if ($r.Blocked)     { $marks += 'блок' }
        if ($r.InWhitelist) { $marks += 'белый' }
        if ($r.Random)      { $marks += 'адрес меняется' }
        Write-Host ('{0,-20} {1,-19} {2,-14} {3,-11} {4,-16} {5}' -f `
                    $r.Alias, $r.Mac, (Get-LinkText $r), (Get-StateText $r), $r.Ip, ($marks -join ', '))
    }
    Write-Host ''
    Write-Host "Всего устройств: $($inv.Count)"
    return
}

# -------------------------------------------------------------------- окно ---

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$COL_NAME  = 0
$COL_MAC   = 1
$COL_LINK  = 2
$COL_STATE = 3
$COL_IP    = 4
$COL_BLOCK = 5
$COL_WHITE = 6

$colorWarn     = [System.Drawing.Color]::FromArgb(178, 34, 34)
$colorDisabled = [System.Drawing.Color]::FromArgb(240, 240, 240)

$form = New-Object System.Windows.Forms.Form
$form.Text          = 'Устройства в сети'
$form.Size          = New-Object System.Drawing.Size(940, 580)
$form.StartPosition = 'CenterScreen'
$form.Font          = New-Object System.Drawing.Font('Segoe UI', 9.5)
$form.MinimumSize   = New-Object System.Drawing.Size(780, 440)

$fontBold = New-Object System.Drawing.Font($form.Font, [System.Drawing.FontStyle]::Bold)

$lblHint = New-Object System.Windows.Forms.Label
$lblHint.Location = New-Object System.Drawing.Point(14, 10)
$lblHint.Size     = New-Object System.Drawing.Size(900, 34)
$lblHint.Anchor   = 'Top,Left,Right'
$lblHint.Text     = ('Отметьте, кого заблокировать и кого держать в белом списке Wi-Fi, затем нажмите «Применить».' + [Environment]::NewLine +
                     'Имя можно исправить прямо в таблице — оно станет именем ярлыка.')
$form.Controls.Add($lblHint)

$grid = New-Object System.Windows.Forms.DataGridView
$grid.Location = New-Object System.Drawing.Point(14, 50)
$grid.Size     = New-Object System.Drawing.Size(900, 420)
$grid.Anchor   = 'Top,Left,Right,Bottom'
$grid.AllowUserToAddRows          = $false
$grid.AllowUserToDeleteRows       = $false
$grid.AllowUserToResizeRows       = $false
$grid.RowHeadersVisible           = $false
$grid.MultiSelect                 = $false
$grid.SelectionMode               = 'CellSelect'
$grid.BackgroundColor             = [System.Drawing.Color]::White
$grid.BorderStyle                 = 'FixedSingle'
$grid.ColumnHeadersHeightSizeMode = 'AutoSize'
$grid.EditMode                    = 'EditOnEnter'
$grid.ShowCellToolTips            = $true
$form.Controls.Add($grid)

function Add-GridColumn([string]$Header, [int]$Width, [bool]$IsCheck, [bool]$ReadOnly) {
    if ($IsCheck) {
        $c = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
    } else {
        $c = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    }
    $c.HeaderText = $Header
    $c.Width      = $Width
    $c.ReadOnly   = $ReadOnly
    $c.SortMode   = 'NotSortable'
    $grid.Columns.Add($c) | Out-Null
}

Add-GridColumn 'Имя'                160 $false $false
Add-GridColumn 'MAC-адрес'          150 $false $true
Add-GridColumn 'Подключение'        125 $false $true
Add-GridColumn 'Состояние'           95 $false $true
Add-GridColumn 'IP-адрес'           130 $false $true
Add-GridColumn 'Блокировать'        100 $true  $false
Add-GridColumn 'Белый список Wi-Fi' 130 $true  $false

$lblLegend = New-Object System.Windows.Forms.Label
$lblLegend.Location  = New-Object System.Drawing.Point(14, 478)
$lblLegend.Size      = New-Object System.Drawing.Size(900, 34)
$lblLegend.Anchor    = 'Bottom,Left,Right'
$lblLegend.ForeColor = [System.Drawing.Color]::Gray
$lblLegend.Text      = ('Красным — случайные адреса: устройство меняет их при переподключении, и правило перестаёт действовать.' + [Environment]::NewLine +
                       'Белый список работает только по Wi-Fi и только когда он включён; его состояние показывает окно «Статус».')
$form.Controls.Add($lblLegend)

$lblTime = New-Object System.Windows.Forms.Label
$lblTime.Location  = New-Object System.Drawing.Point(14, 516)
$lblTime.Size      = New-Object System.Drawing.Size(360, 22)
$lblTime.Anchor    = 'Bottom,Left'
$lblTime.ForeColor = [System.Drawing.Color]::Gray
$form.Controls.Add($lblTime)

$btnRefresh = New-Object System.Windows.Forms.Button
$btnRefresh.Text     = 'Обновить'
$btnRefresh.Location = New-Object System.Drawing.Point(624, 512)
$btnRefresh.Size     = New-Object System.Drawing.Size(90, 28)
$btnRefresh.Anchor   = 'Bottom,Right'
$form.Controls.Add($btnRefresh)

$btnApply = New-Object System.Windows.Forms.Button
$btnApply.Text     = 'Применить'
$btnApply.Location = New-Object System.Drawing.Point(720, 512)
$btnApply.Size     = New-Object System.Drawing.Size(100, 28)
$btnApply.Anchor   = 'Bottom,Right'
$form.Controls.Add($btnApply)

$btnClose = New-Object System.Windows.Forms.Button
$btnClose.Text     = 'Закрыть'
$btnClose.Location = New-Object System.Drawing.Point(826, 512)
$btnClose.Size     = New-Object System.Drawing.Size(88, 28)
$btnClose.Anchor   = 'Bottom,Right'
$btnClose.Add_Click({ $form.Close() })
$form.Controls.Add($btnClose)

# ------------------------------------------------------------------ логика ---

function Update-View {
    $form.Cursor        = 'WaitCursor'
    $btnRefresh.Enabled = $false
    $btnApply.Enabled   = $false
    try {
        $inventory = Get-DeviceInventory
        $grid.Rows.Clear()
        foreach ($r in $inventory) {
            $i = $grid.Rows.Add($r.Alias, $r.Mac, (Get-LinkText $r), (Get-StateText $r),
                                $r.Ip, $r.Blocked, $r.InWhitelist)
            $row = $grid.Rows[$i]
            $row.Tag = $r

            if ($r.Random) {
                $row.Cells[$COL_MAC].Style.ForeColor = $colorWarn
                $row.Cells[$COL_MAC].Style.Font      = $fontBold
                $row.Cells[$COL_MAC].ToolTipText     =
                    'Случайный адрес. Устройство сменит его при переподключении, и правило перестанет работать. Отключите рандомизацию MAC в настройках Wi-Fi на самом устройстве.'
            }

            # Белый список — фильтр беспроводной сети. Для устройства,
            # замеченного только на LAN-порту, галочка не имеет смысла.
            if ($r.Wired -and -not $r.Wireless) {
                $cell = $row.Cells[$COL_WHITE]
                $cell.ReadOnly         = $true
                $cell.Style.BackColor  = $colorDisabled
                $cell.ToolTipText      = 'Устройство подключено кабелем. Белый список действует только на Wi-Fi.'
            }

            if (-not $r.Online) { $row.Cells[$COL_STATE].Style.ForeColor = [System.Drawing.Color]::Gray }
        }
        $lblTime.Text = "Обновлено: $(Get-Date -Format 'HH:mm:ss') · устройств: $($inventory.Count)"
    }
    catch {
        $lblTime.Text = 'Не удалось получить данные'
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Ошибка связи с роутером',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
    }
    finally {
        $btnRefresh.Enabled = $true
        $btnApply.Enabled   = $true
        $form.Cursor        = 'Default'
    }
}

function Get-GridState {
    <# Снимок таблицы: что стоит в галочках и полях прямо сейчас. #>
    $grid.EndEdit() | Out-Null
    $items = @()
    foreach ($row in $grid.Rows) {
        if (-not $row.Tag) { continue }
        $items += [pscustomobject]@{
            Row   = $row.Tag
            Alias = ([string]$row.Cells[$COL_NAME].Value).Trim()
            Block = [bool]$row.Cells[$COL_BLOCK].Value
            White = [bool]$row.Cells[$COL_WHITE].Value
        }
    }
    return $items
}

function Test-GridState($Items) {
    <# Проверяем имена до любой записи: они станут ключами файлов и ярлыков. #>
    $errors = @()
    $seen   = @{}
    foreach ($e in $Items) {
        $needsName = $e.Block -or $e.White -or $e.Row.InDevices -or $e.Row.InWhitelist
        if (-not $needsName) { continue }
        if (-not $e.Alias) {
            $errors += "У устройства $($e.Row.Mac) пустое имя."
            continue
        }
        if ($e.Alias -ne (Get-SafeAlias $e.Alias)) {
            $errors += "Имя «$($e.Alias)» содержит символы, недопустимые в имени файла ярлыка."
            continue
        }
        $key = $e.Alias.ToLower()
        if ($seen.ContainsKey($key)) {
            $errors += "Имя «$($e.Alias)» встречается дважды — имена должны быть разными."
        } else {
            $seen[$key] = $true
        }
    }
    return $errors
}

function Invoke-Apply {
    $items  = Get-GridState
    $errors = Test-GridState $items
    if ($errors.Count -gt 0) {
        [System.Windows.Forms.MessageBox]::Show(($errors -join [Environment]::NewLine),
            'Проверьте имена', [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
        return
    }

    $blockOn  = @($items | Where-Object { $_.Block -and -not $_.Row.Blocked })
    $blockOff = @($items | Where-Object { -not $_.Block -and $_.Row.Blocked })
    $wlOn     = @($items | Where-Object { $_.White -and -not $_.Row.InWhitelist })
    $wlOff    = @($items | Where-Object { -not $_.White -and $_.Row.InWhitelist })
    $renamed  = @($items | Where-Object { $_.Alias -ne $_.Row.Alias -and ($_.Row.InDevices -or $_.Block) })

    if ($blockOn.Count + $blockOff.Count + $wlOn.Count + $wlOff.Count + $renamed.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('Ничего не изменено.', 'Устройства в сети',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        return
    }

    # Блокировать собственный адаптер — значит остаться без роутера.
    $localMacs = Get-LocalMacAddresses
    $self = @($blockOn | Where-Object { $localMacs -contains $_.Row.Mac })
    if ($self.Count -gt 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "$($self[0].Row.Mac) — сетевой адаптер этого компьютера. Его блокировка отрезала бы вас от роутера.",
            'Так нельзя', [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
        return
    }

    # --- подтверждение ---------------------------------------------------
    $lines = @('Будет сделано:', '')
    foreach ($e in $blockOn)  { $lines += "  заблокировать      $($e.Alias)  ($($e.Row.Mac))" }
    foreach ($e in $blockOff) { $lines += "  разблокировать     $($e.Alias)  ($($e.Row.Mac))" }
    foreach ($e in $wlOn)     { $lines += "  в белый список     $($e.Alias)  ($($e.Row.Mac))" }
    foreach ($e in $wlOff)    { $lines += "  убрать из белого   $($e.Alias)  ($($e.Row.Mac))" }
    foreach ($e in $renamed)  { $lines += "  переименовать      $($e.Row.Alias) → $($e.Alias)" }

    $risky = @($blockOn + $wlOn | Where-Object { $_.Row.Random })
    if ($risky.Count -gt 0) {
        $lines += ''
        $lines += 'Внимание: у этих устройств случайный адрес, и правило перестанет'
        $lines += 'работать после их переподключения:'
        foreach ($e in $risky) { $lines += "  $($e.Alias)  ($($e.Row.Mac))" }
    }

    if ($wlOff.Count -gt 0) {
        $lines += ''
        $lines += 'Адреса, убранные из белого списка, будут удалены и с роутера.'
    }

    $lines += ''
    $lines += 'Продолжить?'

    $answer = [System.Windows.Forms.MessageBox]::Show(($lines -join [Environment]::NewLine),
        'Подтверждение', [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question)
    if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }

    # --- выполнение -------------------------------------------------------
    $form.Cursor        = 'WaitCursor'
    $btnApply.Enabled   = $false
    $btnRefresh.Enabled = $false
    $report = @()
    try {
        # Имена: в devices.json попадают те, кто там уже был, и те, кого
        # сейчас блокируют — именно для них имеет смысл ярлык.
        $aliasEntries = @()
        foreach ($e in $items) {
            if ($e.Row.InDevices -or $e.Block) {
                $aliasEntries += [pscustomobject]@{ Alias = $e.Alias; Mac = $e.Row.Mac }
            }
        }
        Save-DeviceAliases $aliasEntries
        $report += "devices.json: записей $($aliasEntries.Count)"

        # Белый список.
        if ($wlOn.Count -gt 0 -or $wlOff.Count -gt 0 -or $renamed.Count -gt 0) {
            $wlEntries = @()
            foreach ($e in $items) {
                if (-not $e.White) { continue }
                $wlEntries += [pscustomobject]@{ Alias = $e.Alias; Mac = $e.Row.Mac; Band = $e.Row.WlBand }
            }
            Save-Whitelist $wlEntries
            $report += "whitelist.json: записей $($wlEntries.Count)"
        }

        # Блокировки — через основной скрипт, чтобы правила писались
        # ровно одним способом.
        foreach ($e in $blockOn) {
            & $MainScript block -Mac $e.Row.Mac -Router $Router -User $User | Out-Null
            $report += "заблокировано: $($e.Alias)"
        }
        foreach ($e in $blockOff) {
            & $MainScript unblock -Mac $e.Row.Mac -Router $Router -User $User | Out-Null
            $report += "разблокировано: $($e.Alias)"
        }

        # Список на роутере приводим в соответствие с файлом: без этого
        # снятая галочка правила бы файл, но не отзывала доступ.
        if ($wlOn.Count -gt 0 -or $wlOff.Count -gt 0) {
            if (Test-Path $WhitelistScript) {
                $syncLog = & $WhitelistScript sync -Text -Router $Router -User $User 2>&1 | Out-String
                $report += ''
                $report += $syncLog.Trim()
            } else {
                $report += 'wifi-whitelist.ps1 рядом не найден — список на роутере не обновлён.'
            }
        }

        [System.Windows.Forms.MessageBox]::Show(($report -join [Environment]::NewLine),
            'Готово', [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
    }
    catch {
        $body = $_.Exception.Message
        if ($report.Count -gt 0) {
            $body = ($report -join [Environment]::NewLine) + [Environment]::NewLine + [Environment]::NewLine +
                    'Дальше произошла ошибка:' + [Environment]::NewLine + $body
        }
        [System.Windows.Forms.MessageBox]::Show($body, 'Ошибка',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
    }
    finally {
        $btnApply.Enabled   = $true
        $btnRefresh.Enabled = $true
        $form.Cursor        = 'Default'
    }

    Update-View
}

$btnRefresh.Add_Click({ Update-View })
$btnApply.Add_Click({ Invoke-Apply })
$form.Add_Shown({ $form.Activate(); Update-View })

[void]$form.ShowDialog()
