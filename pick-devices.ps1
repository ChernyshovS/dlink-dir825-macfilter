<#
.SYNOPSIS
    Окно выбора устройств: кого заблокировать и кого держать в белом списке.

.DESCRIPTION
    Показывает устройства, которые роутер видит сейчас или видел за последние
    сутки, и позволяет отметить галочками, кого блокировать и кого пускать
    по белому списку Wi-Fi. Имя можно исправить прямо в таблице — оно станет
    ключом в devices.json.

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
$CFG_WIFI     = 42   # политика белых списков Wi-Fi по диапазонам

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
    <#  Имя — ключ в devices.json и аргумент -Name в командной строке.
        Убираем символы, которые там мешают: кавычки, вертикальную черту,
        угловые скобки и прочее в том же роде.

        Пробелы законны и остаются на месте: замена их на дефисы приводила
        к тому, что имя из двух слов отвергалось с сообщением про
        недопустимые символы. Точку и пробелы по краям срезаем. #>
    $clean = ([string]$Name) -replace '[\\/:\*\?"<>\|]', '-'
    $clean = $clean -replace '\s+', ' '
    $clean = $clean.Trim([char[]]@(' ', '.'))
    if ($clean.Length -gt 24) { $clean = $clean.Substring(0, 24).Trim() }
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
            Seen        = $false
            Blocked     = $false
            HasRule     = $false
            InDevices   = $false
            InWhitelist = $false
            WlBand      = 'both'
            Random      = (Test-RandomMac $key)
        }
    }
    return $Map[$key]
}

# Сводка о режимах фильтрации: то, ради чего раньше открывали отдельное
# окно статуса. Складывается из уже прочитанной конфигурации 74 и одного
# дополнительного чтения конфигурации 42.
$script:Summary = $null

# Конфигурация 42 целиком: нужна ниже, если whitelist.json ещё не создан.
$script:WifiConfig = $null

function Set-StateSummary($Firewall) {
    # Политика межсетевого экрана — нулевой элемент списка, у него нет
    # адреса. Он же решает, чёрный это список или белый.
    $base = @($Firewall.macfilter) | Where-Object { $null -eq $_.mac } | Select-Object -First 1
    if ($base -and $base.state) {
        $fwText = 'запрещать всё, кроме исключений (белый список)'
    } elseif ($base) {
        $fwText = 'разрешать всё, кроме исключений (чёрный список)'
    } else {
        $fwText = 'разрешать всё — фильтр ещё не настроен'
    }

    # Белые списки Wi-Fi. Курсор выбора сети при чтении не нужен: ответ
    # одинаков с ним и без него, а лишняя запись изнашивала бы флеш-память
    # и оставляла бы на роутере флаг «конфигурация изменена».
    $wifi = Read-RouterConfig -Id $CFG_WIFI
    # Пригодится при сборке списка устройств: второй раз ту же конфигурацию
    # читать незачем, это лишний круг к роутеру ради тех же данных.
    $script:WifiConfig = $wifi

    $onBands = @()
    $listed  = 0
    foreach ($b in @(@{ P = ''; T = '2,4 ГГц' }, @{ P = '5G_'; T = '5 ГГц' })) {
        if ([int]$wifi."$($b.P)AccessPolicy" -eq 1) { $onBands += $b.T }
        $lst = $wifi."$($b.P)MacFilterList"
        if ($lst) {
            $listed += @($lst.PSObject.Properties | Where-Object { $_.Name -ne 'max_instance' }).Count
        }
    }

    if ($onBands.Count -gt 0) {
        $wlText = "ВКЛЮЧЁН ($($onBands -join ' и ')) — к Wi-Fi пускает только отмеченных, записей $listed"
    } else {
        $wlText = 'выключен — Wi-Fi открыт для всех'
    }

    $script:Summary = [pscustomobject]@{
        Firewall = $fwText
        WifiOn   = ($onBands.Count -gt 0)
        WifiText = $wlText
    }
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

        # reachable — роутер подтвердил связь; stale — запись ещё есть, но
        # связь не подтверждена. Приравнивать stale к присутствию нельзя:
        # выключенный компьютер какое-то время висит в списке именно так.
        # Но и к отсутствию тоже — поэтому это отдельное состояние.
        $r.Seen = $true
        if ([string]$c.flags -match 'reachable') { $r.Online = $true }

        if ($c.name -eq 'WLAN') { $r.Wireless = $true }
        elseif ($c.name)        { $r.Wired    = $true }
    }

    # Беспроводные соединения — единственный надёжный признак того, что
    # устройство именно на Wi-Fi, и единственный источник диапазона.
    foreach ($w in @($info.'64')) {
        if (-not $w.mac) { continue }
        # Присутствие здесь означает установленное соединение с точкой
        # доступа, даже если устройство спит и потому числится stale.
        $r = Get-Slot $map $w.mac
        $r.Wireless = $true
        $r.Online   = $true
        $r.Seen     = $true
        if ($w.band)     { $r.Band     = [string]$w.band }
        if ($w.hostname) { $r.Hostname = [string]$w.hostname }
    }

    # Текущие блокировки.
    $fw = Read-RouterConfig -Id $CFG_FIREWALL
    foreach ($f in @($fw.macfilter)) {
        if ($null -eq $f.mac) { continue }
        $r = Get-Slot $map $f.mac
        # Правило может существовать выключенным: разблокировка его гасит,
        # а не удаляет. Для уборки списков важно именно наличие.
        $r.HasRule = $true
        $r.Blocked = ([bool]$f.state) -and ($f.enable -eq 'DROP')
    }

    Set-StateSummary $fw

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

    # Белый список. Обычно источник истины — файл: по нему sync приводит
    # список на роутере в соответствие, удаляя всё, чего в файле нет.
    $script:WhitelistFromRouter = 0
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
    else {
        # Файла нет — на новом компьютере это обычное дело: он не приезжает
        # ни из репозитория, ни из первичной настройки. Считать список
        # пустым нельзя: тогда первое же «Применить» вызвало бы sync, и
        # список на роутере схлопнулся бы до отмеченного здесь, то есть
        # до пустого. Поэтому, пока файла нет, отметки берём с роутера.
        foreach ($b in @(@{ P = ''; Key = '2.4' }, @{ P = '5G_'; Key = '5' })) {
            $lst = $script:WifiConfig."$($b.P)MacFilterList"
            if (-not $lst) { continue }
            foreach ($p in $lst.PSObject.Properties) {
                if ($p.Name -eq 'max_instance' -or -not $p.Value.mac) { continue }
                $r = Get-Slot $map $p.Value.mac
                if ($r.InWhitelist) {
                    # Один и тот же адрес в обоих списках — это и есть both.
                    if ($r.WlBand -ne $b.Key) { $r.WlBand = 'both' }
                } else {
                    $r.WlBand      = $b.Key
                    $r.InWhitelist = $true
                    $script:WhitelistFromRouter++
                }
                if (-not $r.Alias -and $p.Value.hostname) { $r.Alias = [string]$p.Value.hostname }
            }
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
                         @{ Expression = 'Seen';    Descending = $true },
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
    if ($Row.Seen)   { return 'не отвечает' }
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
    Write-Host "Межсетевой экран:   $($script:Summary.Firewall)"
    Write-Host 'Белый список Wi-Fi: ' -NoNewline
    if ($script:Summary.WifiOn) {
        Write-Host $script:Summary.WifiText -ForegroundColor Red
    } else {
        Write-Host $script:Summary.WifiText -ForegroundColor Green
    }
    if ($script:WhitelistFromRouter -gt 0) {
        Write-Host '                    отметки списка прочитаны с роутера: whitelist.json ещё нет'
    }
    Write-Host ''
    Write-Host ('{0,-20} {1,-19} {2,-14} {3,-11} {4,-16} {5}' -f `
                'Имя', 'MAC-адрес', 'Подключение', 'Состояние', 'IP-адрес', 'Списки')
    Write-Host ('-' * 105)
    foreach ($r in $inv) {
        $marks = @()
        if ($r.Blocked)     { $marks += 'блок' }
        if ($r.InWhitelist) { $marks += 'белый' }
        if ($r.Random)      { $marks += 'случайный адрес' }
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

$colorOk       = [System.Drawing.Color]::FromArgb(34, 120, 34)
$colorWarn     = [System.Drawing.Color]::FromArgb(178, 34, 34)

$form = New-Object System.Windows.Forms.Form
$form.Text          = 'Устройства в сети'
$form.StartPosition = 'CenterScreen'
$form.Font          = New-Object System.Drawing.Font('Segoe UI', 9.5)

# Желаемый размер — 940x680, но на маленьком экране окно не должно
# оказаться больше рабочей области: заголовок ушёл бы за верхнюю кромку,
# а нижние кнопки скрылись бы за панелью задач. Нижнюю границу тоже
# приходится опускать, иначе она не даст окну ужаться до экрана, — и
# следить, чтобы желаемый размер не оказался меньше самой этой границы.
$work = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
$minW = [Math]::Min(860, $work.Width)
$minH = [Math]::Min(560, $work.Height)
$form.MinimumSize = New-Object System.Drawing.Size($minW, $minH)
$form.Size = New-Object System.Drawing.Size(
    [Math]::Max($minW, [Math]::Min(940, $work.Width - 20)),
    [Math]::Max($minH, [Math]::Min(680, $work.Height - 20)))

# Раскладка считается от фактических размеров клиентской области, а не от
# желаемых. Привязка Anchor тут не помощник: она хранит расстояние до края
# таким, каким оно было в момент добавления элемента, а размер окна задан
# раньше, чем добавлены элементы, — на ужатом окне нижний ряд создавался
# сразу за кромкой и там же оставался при любом изменении размера.
# При 940x680 все числа ниже совпадают с прежними; на 1366x768 при 125%
# по высоте остаётся около 574 вместо нужных 641 — не хватало 120 точек.
$clientW    = $form.ClientSize.Width
$clientH    = $form.ClientSize.Height
$rowTime    = $clientH - 70   # строка состояния: две строки текста и отступ
$rowButtons = $rowTime + 4
$rowLegend  = $rowTime - 66   # три строки пояснений над ней
$gridTop    = 102
$gridHeight = [Math]::Max(120, $rowLegend - $gridTop - 6)

$fontBold = New-Object System.Drawing.Font($form.Font, [System.Drawing.FontStyle]::Bold)

# Два режима фильтрации, каждый со своим смыслом: межсетевой экран режет
# интернет отмеченным устройствам, белый список Wi-Fi не пускает в сеть
# неотмеченные. Раньше это показывало отдельное окно.
$lblFirewall = New-Object System.Windows.Forms.Label
$lblFirewall.Location = New-Object System.Drawing.Point(14, 10)
$lblFirewall.Size     = New-Object System.Drawing.Size(($clientW - 24), 20)
$lblFirewall.Anchor   = 'Top,Left,Right'
$form.Controls.Add($lblFirewall)

$lblWifi = New-Object System.Windows.Forms.Label
$lblWifi.Location = New-Object System.Drawing.Point(14, 32)
$lblWifi.Size     = New-Object System.Drawing.Size(($clientW - 154), 20)
# Обе стороны: закреплённая только слева, подпись не сжималась при
# сужении окна и наезжала на кнопку, закрывая её собой.
$lblWifi.Anchor   = 'Top,Left,Right'
$form.Controls.Add($lblWifi)

# Кнопка одна и меняет надпись по состоянию. Двумя ярлыками это делалось
# потому, что состояние было не видно и легко было нажать не в ту сторону;
# здесь оно написано прямо слева от кнопки — поэтому и надпись короткая,
# что именно включается, сказано в подписи и в подсказке.
$btnWhitelist = New-Object System.Windows.Forms.Button
$btnWhitelist.Location = New-Object System.Drawing.Point(($clientW - 130), 29)
$btnWhitelist.Size     = New-Object System.Drawing.Size(120, 26)
$btnWhitelist.Anchor   = 'Top,Right'
$form.Controls.Add($btnWhitelist)

$tips = New-Object System.Windows.Forms.ToolTip

$lblHint = New-Object System.Windows.Forms.Label
$lblHint.Location = New-Object System.Drawing.Point(14, 58)
$lblHint.Size     = New-Object System.Drawing.Size(($clientW - 24), 40)
$lblHint.Anchor   = 'Top,Left,Right'
$lblHint.Text     = ('Отметьте, кого заблокировать и кого держать в белом списке Wi-Fi, затем нажмите «Применить».' + [Environment]::NewLine +
                     'Имя можно исправить прямо в таблице.')
$form.Controls.Add($lblHint)

$grid = New-Object System.Windows.Forms.DataGridView
$grid.Location = New-Object System.Drawing.Point(14, $gridTop)
$grid.Size     = New-Object System.Drawing.Size(($clientW - 24), $gridHeight)
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
Add-GridColumn 'MAC-адрес'          140 $false $true
Add-GridColumn 'Подключение'        105 $false $true
Add-GridColumn 'Состояние'           90 $false $true
Add-GridColumn 'IP-адрес'           105 $false $true
Add-GridColumn 'Блокировать'         95 $true  $false
Add-GridColumn 'Белый список Wi-Fi' 130 $true  $false

# Столбец имени забирает остаток ширины. Иначе сумма столбцов почти равна
# ширине таблицы, и стоит появиться вертикальному ползунку, как места не
# хватает и вылезает ещё и горизонтальный. Нижняя граница — чтобы при
# сжатии окна столбец не схлопнулся в ничто.
$grid.Columns[$COL_NAME].AutoSizeMode = 'Fill'
$grid.Columns[$COL_NAME].MinimumWidth = 110

# Удаление — действие редкое и необратимое, поэтому оно не в галочках, а по
# правой кнопке: промахнуться мимо галочки легко, мимо пункта меню трудно.
# Нужно оно тем, у кого адреса плодятся: телефон с рандомизацией оставляет
# после себя мёртвый адрес всякий раз, когда сменит его.
$script:MenuRow = $null

$gridMenu = New-Object System.Windows.Forms.ContextMenuStrip
$miForget = $gridMenu.Items.Add('Убрать устройство из списков')
$grid.ContextMenuStrip = $gridMenu

# Правый щелчок сам по себе строку не выбирает — запоминаем, по какой попали.
$grid.Add_CellMouseDown({
    param($sender, $e)
    if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Right -and $e.RowIndex -ge 0) {
        $script:MenuRow = $grid.Rows[$e.RowIndex]
        # Ставим текущей ячейкой адрес, а не имя: имя редактируемое, и фокус
        # на нём открыл бы правку прямо под контекстным меню.
        $grid.CurrentCell = $script:MenuRow.Cells[$COL_MAC]
    }
})

$gridMenu.Add_Opening({
    if ($script:MenuRow -and $script:MenuRow.Tag) {
        $miForget.Text = "Убрать «$($script:MenuRow.Cells[$COL_NAME].Value)» из списков"
    } else {
        $miForget.Text = 'Убрать устройство из списков'
    }
})

$lblLegend = New-Object System.Windows.Forms.Label
$lblLegend.Location  = New-Object System.Drawing.Point(14, $rowLegend)
$lblLegend.Size      = New-Object System.Drawing.Size(($clientW - 24), 60)
$lblLegend.Anchor    = 'Bottom,Left,Right'
$lblLegend.ForeColor = [System.Drawing.Color]::Gray
$lblLegend.Text      = ('Красным — случайные адреса: устройство может сменить такой адрес, и правило перестанет действовать.' + [Environment]::NewLine +
                       'Галочки белого списка действуют, только когда он включён — кнопка справа сверху.' + [Environment]::NewLine +
                       '«Не отвечает» — роутер помнит устройство, но связь не подтверждена: обычно оно только что отключилось.')
$form.Controls.Add($lblLegend)

# Одна строка состояния на две роли: обычно показывает время обновления,
# а пока есть несохранённое — предупреждение. Двумя подписями рядом это
# не сделать: при масштабировании экрана они налезают друг на друга и на
# кнопки. Высоты хватает на две строки, поэтому длинный текст переносится,
# а не обрезается.
$lblTime = New-Object System.Windows.Forms.Label
$lblTime.Location  = New-Object System.Drawing.Point(14, $rowTime)
$lblTime.Size      = New-Object System.Drawing.Size([Math]::Min(430, $clientW - 330), 40)
$lblTime.Anchor    = 'Bottom,Left'
$lblTime.ForeColor = [System.Drawing.Color]::Gray
$form.Controls.Add($lblTime)

$btnRefresh = New-Object System.Windows.Forms.Button
$btnRefresh.Text     = 'Обновить'
$btnRefresh.Location = New-Object System.Drawing.Point(($clientW - 300), $rowButtons)
$btnRefresh.Size     = New-Object System.Drawing.Size(90, 28)
$btnRefresh.Anchor   = 'Bottom,Right'
$form.Controls.Add($btnRefresh)

$btnApply = New-Object System.Windows.Forms.Button
$btnApply.Text     = 'Применить'
$btnApply.Location = New-Object System.Drawing.Point(($clientW - 204), $rowButtons)
$btnApply.Size     = New-Object System.Drawing.Size(100, 28)
$btnApply.Anchor   = 'Bottom,Right'
$form.Controls.Add($btnApply)

$btnClose = New-Object System.Windows.Forms.Button
$btnClose.Text     = 'Закрыть'
$btnClose.Location = New-Object System.Drawing.Point(($clientW - 98), $rowButtons)
$btnClose.Size     = New-Object System.Drawing.Size(88, 28)
$btnClose.Anchor   = 'Bottom,Right'
$btnClose.Add_Click({ $form.Close() })
$form.Controls.Add($btnClose)

# ------------------------------------------------------------------ логика ---

# Заполнение таблицы тоже меняет ячейки, поэтому на время загрузки отметку
# о несохранённом надо глушить.
$script:Loading = $false

# Роутер помнит клиента, только пока тот подаёт признаки жизни: тихий
# компьютер на кабеле пропадает из его списка, и тип подключения обнулился
# бы прямо на глазах. Запоминаем последнее известное на время работы окна.
$script:LastLink = @{}

# Текст последнего обновления, чтобы вернуть его в строку состояния,
# когда предупреждение больше не нужно.
$script:LastRefreshText = ''

# Включать белый список поверх несохранённых галочек нельзя: подействует
# старый файл, а не то, что человек видит на экране.
$script:Dirty = $false

function Set-DirtyState([bool]$On) {
    $script:Dirty = $On
    if ($On) {
        $lblTime.Text      = 'Изменения не сохранены — нажмите «Применить»'
        $lblTime.ForeColor = $colorWarn
        $lblTime.Font      = $fontBold
    } else {
        $lblTime.Text      = $script:LastRefreshText
        $lblTime.ForeColor = [System.Drawing.Color]::Gray
        $lblTime.Font      = $form.Font
    }
}

function Update-View {
    $form.Cursor        = 'WaitCursor'
    $btnRefresh.Enabled = $false
    $btnApply.Enabled   = $false
    $script:Loading     = $true
    try {
        $inventory = Get-DeviceInventory

        $lblFirewall.Text = "Межсетевой экран: $($script:Summary.Firewall)"
        $lblWifi.Text     = "Белый список Wi-Fi: $($script:Summary.WifiText)"
        if ($script:Summary.WifiOn) {
            $lblWifi.ForeColor = $colorWarn
            $lblWifi.Font      = $fontBold
            $btnWhitelist.Text = 'Выключить'
            $tips.SetToolTip($btnWhitelist, 'Выключить белый список Wi-Fi: сеть снова откроется для всех устройств.')
        } else {
            $lblWifi.ForeColor = $colorOk
            $lblWifi.Font      = $form.Font
            $btnWhitelist.Text = 'Включить'
            $tips.SetToolTip($btnWhitelist, 'Включить белый список Wi-Fi: к сети смогут подключиться только отмеченные устройства.')
        }
        $btnWhitelist.Enabled = (Test-Path $WhitelistScript)

        $grid.Rows.Clear()
        foreach ($r in $inventory) {
            $link      = Get-LinkText $r
            $linkKnown = ($link -ne '—')
            if ($linkKnown) {
                $script:LastLink[$r.Mac] = $link
            } elseif ($script:LastLink.ContainsKey($r.Mac)) {
                $link = $script:LastLink[$r.Mac]
            }

            $i = $grid.Rows.Add($r.Alias, $r.Mac, $link, (Get-StateText $r),
                                $r.Ip, $r.Blocked, $r.InWhitelist)
            $row = $grid.Rows[$i]
            $row.Tag = $r

            if (-not $linkKnown -and $link -ne '—') {
                $row.Cells[$COL_LINK].Style.ForeColor = [System.Drawing.Color]::Gray
                $row.Cells[$COL_LINK].ToolTipText     = 'Последнее известное подключение. Сейчас роутер это устройство не видит.'
            }

            if ($r.Random) {
                $row.Cells[$COL_MAC].Style.ForeColor = $colorWarn
                $row.Cells[$COL_MAC].Style.Font      = $fontBold
                $row.Cells[$COL_MAC].ToolTipText     =
                    'Адрес придуман самим устройством, а не выдан изготовителем. Он может смениться — тогда правило останется висеть на прежнем адресе. Чинится отключением рандомизации MAC в настройках сети на самом устройстве, но учтите: устройство вернётся под другим адресом и появится в таблице новой строкой.'
            }

            # По Wi-Fi компьютер выходит через другой адаптер, со своим
            # адресом, и попадает в список отдельной строкой — записи на
            # адрес проводной карты беспроводной фильтр не касается вовсе.
            # Галочку тем не менее не запрещаем: «проводное» — это одно
            # наблюдение, а запрет получался односторонним. Пока устройство
            # было выключено, тип подключения неизвестен и снять галочку
            # удавалось, а вернуть после включения по кабелю — уже нет.
            if ($r.Wired -and -not $r.Wireless) {
                $row.Cells[$COL_WHITE].ToolTipText = 'Сейчас устройство подключено кабелем.'
            }

            # Разблокировка гасит правило, а не удаляет его: устройство не
            # заблокировано и галочка снята, но запись на роутере осталась,
            # и в выводе status такая строка видна. Иначе непонятно, откуда
            # там устройства без галочки.
            if ($r.HasRule -and -not $r.Blocked) {
                $row.Cells[$COL_BLOCK].ToolTipText =
                    'Устройство не заблокировано, но правило на роутере осталось — выключенным. Так работает разблокировка: запись хранится, чтобы заблокировать снова одним запросом. Убрать её насовсем — правым щелчком по строке.'
            }

            if (-not $r.Online) { $row.Cells[$COL_STATE].Style.ForeColor = [System.Drawing.Color]::Gray }
        }
        $script:LastRefreshText = "Обновлено: $(Get-Date -Format 'HH:mm:ss') · устройств: $($inventory.Count)"
        if ($script:WhitelistFromRouter -gt 0) {
            $script:LastRefreshText += " · белый список прочитан с роутера, whitelist.json ещё нет"
        }
    }
    catch {
        $lblFirewall.Text = 'Межсетевой экран: неизвестно'
        $lblWifi.Text     = 'Белый список Wi-Fi: неизвестно'
        $lblWifi.ForeColor = [System.Drawing.Color]::Gray
        $lblWifi.Font      = $form.Font
        $script:LastRefreshText = 'Не удалось получить данные'
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Ошибка связи с роутером',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
    }
    finally {
        $script:Loading     = $false
        $btnRefresh.Enabled = $true
        $btnApply.Enabled   = $true
        $form.Cursor        = 'Default'
        Set-DirtyState $false
    }
}

# Галочка не считается изменённой, пока фокус не ушёл из ячейки. Без этого
# отметка о несохранённом появлялась бы с опозданием на одно нажатие.
$grid.Add_CurrentCellDirtyStateChanged({
    if ($grid.IsCurrentCellDirty) {
        $grid.CommitEdit([System.Windows.Forms.DataGridViewDataErrorContexts]::Commit) | Out-Null
    }
})
$grid.Add_CellValueChanged({ if (-not $script:Loading) { Set-DirtyState $true } })

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
    <# Проверяем имена до любой записи: они станут ключами в файлах. #>
    $errors = @()
    $seen   = @{}
    foreach ($e in $Items) {
        $needsName = $e.Block -or $e.White -or $e.Row.InDevices -or $e.Row.InWhitelist -or
                     ($e.Alias -ne $e.Row.Alias)
        if (-not $needsName) { continue }
        if (-not $e.Alias) {
            $errors += "У устройства $($e.Row.Mac) пустое имя."
            continue
        }
        if ($e.Alias -ne (Get-SafeAlias $e.Alias)) {
            $errors += "Имя «$($e.Alias)» содержит символы, которые здесь не годятся: \ / : * ? "" < > |"
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
    $renamed  = @($items | Where-Object { $_.Alias -ne $_.Row.Alias })

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
        $lines += 'Внимание: адрес этих устройств придуман ими самими и может смениться.'
        $lines += 'Тогда правило останется висеть на прежнем адресе:'
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
        # devices.json — это реестр имён. В него попадают те, кто там уже
        # был, те, кого сейчас блокируют, и те, кому пользователь вписал имя
        # руками: раз имя набрано, его надо запомнить.
        $aliasEntries = @()
        foreach ($e in $items) {
            if ($e.Row.InDevices -or $e.Block -or ($e.Alias -ne $e.Row.Alias)) {
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

function Invoke-WhitelistToggle {
    <#  Включение и выключение белого списка Wi-Fi. Всю работу и все проверки
        делает wifi-whitelist.ps1: он же покажет, кто сохранит доступ, и
        откажется включать список, в котором нет адреса этого компьютера. #>
    if ($null -eq $script:Summary) { return }

    if ($script:Dirty) {
        [System.Windows.Forms.MessageBox]::Show(
            'В таблице есть несохранённые изменения. Сначала нажмите «Применить», иначе список включится в том виде, в каком он был до правок.',
            'Сначала сохраните', [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
        return
    }

    $action = 'on'
    if ($script:Summary.WifiOn) { $action = 'off' }

    # Без файла wifi-whitelist.ps1 включать список откажется, а отметки в
    # таблице сейчас взяты с роутера. Сохраняем то, что видно: это ровно
    # то, что на роутере и есть, — правки заблокированы проверкой выше.
    if ($action -eq 'on' -and -not (Test-Path $WhitelistFile)) {
        $seed = @()
        foreach ($e in (Get-GridState)) {
            if (-not $e.White) { continue }
            $seed += [pscustomobject]@{ Alias = $e.Alias; Mac = $e.Row.Mac; Band = $e.Row.WlBand }
        }
        Save-Whitelist $seed
    }

    $form.Cursor          = 'WaitCursor'
    $btnWhitelist.Enabled = $false
    try {
        & $WhitelistScript $action -Router $Router -User $User | Out-Null
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Белый список Wi-Fi',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
    }
    finally {
        $btnWhitelist.Enabled = $true
        $form.Cursor          = 'Default'
    }

    Update-View
}

function Invoke-ForgetDevice {
    <#  Убирает устройство отовсюду, где о нём что-то записано: из реестра
        имён, из белого списка (и с роутера вместе с ним) и из правил
        межсетевого экрана.

        Отличается от снятия галочек тем, что запись исчезает, а не гаснет.
        Нужно для адресов, которые уже не вернутся: устройство с
        рандомизацией MAC оставляет мёртвый адрес при каждой смене. #>
    if (-not $script:MenuRow -or -not $script:MenuRow.Tag) { return }
    $r = $script:MenuRow.Tag

    if ($script:Dirty) {
        [System.Windows.Forms.MessageBox]::Show(
            'В таблице есть несохранённые изменения. Сначала нажмите «Применить» или «Обновить».',
            'Сначала разберитесь с правками', [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
        return
    }

    $where = @()
    if ($r.InDevices)   { $where += '  имя в devices.json' }
    if ($r.InWhitelist) { $where += '  запись в белом списке — и в файле, и на роутере' }
    if ($r.HasRule)     { $where += '  правило межсетевого экрана' }

    if ($where.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "Про $($r.Mac) нигде ничего не записано — убирать нечего. Строка исчезнет из таблицы сама, когда роутер забудет об этом адресе.",
            'Нечего убирать', [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        return
    }

    $lines = @("Убрать «$($r.Alias)» ($($r.Mac))?", '', 'Будет удалено:') + $where
    if ($r.Online -or $r.Seen) {
        $lines += ''
        $lines += 'Учтите: устройство сейчас в сети, и после уборки оно снова появится в таблице — уже без имени и без отметок.'
    }
    $lines += ''
    $lines += 'Отменить это будет нельзя.'

    $answer = [System.Windows.Forms.MessageBox]::Show(($lines -join [Environment]::NewLine),
        'Убрать из списков', [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }

    $form.Cursor = 'WaitCursor'
    $report = @()
    try {
        if ($r.HasRule) {
            & $MainScript remove -Mac $r.Mac -Router $Router -User $User | Out-Null
            $report += 'Правило межсетевого экрана удалено.'
        }

        # Файлы пересобираем из таблицы: правок в ней нет, значит она сейчас
        # в точности повторяет содержимое файлов.
        $aliases = @()
        $white   = @()
        foreach ($row in $grid.Rows) {
            $x = $row.Tag
            if (-not $x -or $x.Mac -eq $r.Mac) { continue }
            if ($x.InDevices)   { $aliases += [pscustomobject]@{ Alias = $x.Alias; Mac = $x.Mac } }
            if ($x.InWhitelist) { $white   += [pscustomobject]@{ Alias = $x.Alias; Mac = $x.Mac; Band = $x.WlBand } }
        }

        if ($r.InDevices) {
            Save-DeviceAliases $aliases
            $report += "devices.json: осталось записей $($aliases.Count)."
        }
        if ($r.InWhitelist) {
            Save-Whitelist $white
            $report += "whitelist.json: осталось записей $($white.Count)."
            if (Test-Path $WhitelistScript) {
                $syncLog = & $WhitelistScript sync -Text -Router $Router -User $User 2>&1 | Out-String
                $report += ''
                $report += $syncLog.Trim()
            }
        }

        [System.Windows.Forms.MessageBox]::Show(($report -join [Environment]::NewLine),
            'Убрано', [System.Windows.Forms.MessageBoxButtons]::OK,
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
    finally { $form.Cursor = 'Default' }

    Update-View
}

$miForget.Add_Click({ Invoke-ForgetDevice })
$btnWhitelist.Add_Click({ Invoke-WhitelistToggle })
$btnRefresh.Add_Click({ Update-View })
$btnApply.Add_Click({ Invoke-Apply })
$form.Add_Shown({ $form.Activate(); Update-View })

[void]$form.ShowDialog()
