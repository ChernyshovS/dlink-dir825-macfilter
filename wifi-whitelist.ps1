<#
.SYNOPSIS
    Белый список Wi-Fi: оставить доступ только заранее заданным устройствам.

.DESCRIPTION
    Управляет MAC-фильтром беспроводных сетей роутера D-Link DIR-825ACG1.
    В режиме «включено» к Wi-Fi могут подключиться только устройства из
    сохранённого на роутере списка. sync добавляет записи из whitelist.json после подтверждения.

    Проводные подключения этот фильтр НЕ затрагивает — устройства на LAN-портах
    продолжают работать. Ими управляет отдельный скрипт dlink-macfilter.ps1.

    Фильтр живёт в отдельной конфигурации, поэтому имена сетей, пароли и
    каналы здесь не меняются. Состояние выключенных диапазонов пропускается.
    При нескольких сетях в диапазоне изменяйте фильтр через веб-интерфейс роутера.

.EXAMPLE
    .\wifi-whitelist.ps1 status
    .\wifi-whitelist.ps1 on
    .\wifi-whitelist.ps1 off
    .\wifi-whitelist.ps1 sync
    .\wifi-whitelist.ps1 on -Text -NoConfirm
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('status', 'on', 'off', 'sync', 'patch')]
    [string]$Action = 'status',

    [object[]]$Changes,

    # Работать в консоли, без диалоговых окон.
    [switch]$Text,

    # Не спрашивать подтверждения при включении.
    [switch]$NoConfirm,

    # Игнорировать защиту от самоблокировки. Опасно.
    [switch]$Force,

    [string]$Router = '192.168.0.1',
    [string]$User   = 'admin'
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'router-api.ps1')

$CredFile      = Join-Path $PSScriptRoot 'cred.xml'
$WhitelistFile = Join-Path $PSScriptRoot 'whitelist.json'

$CFG_FILTER = 42   # политика доступа и списки MAC-адресов
$CFG_WIFI   = 35   # настройки Wi-Fi; отсюда берём только состав сетей

# Диапазоны: префикс полей в конфигурации -> человеческое имя и ключ в whitelist.json
$Bands = @(
    [pscustomobject]@{ Prefix = '';     Title = '2.4 ГГц'; Key = '2.4' }
    [pscustomobject]@{ Prefix = '5G_';  Title = '5 ГГц';   Key = '5'   }
)

$POLICY_OFF   = 0
$POLICY_ALLOW = 1   # пускать только тех, кто в списке
$POLICY_DENY  = 2

Initialize-RouterApi -Router $Router -User $User -CredFile $CredFile

# --------------------------------------------------------------- вспомогательное ---

# Устройство сети: включён ли диапазон и сколько в нём сетей. Читается один
# раз за запуск — на этом держатся два решения ниже.
$script:Topology     = $null

function Get-WifiTopology {
    <#  Из настроек Wi-Fi берём ровно два числа на диапазон и ничего больше:
        `Radio` — включено ли радио, `mbssidNum` — сколько сетей в диапазоне.
        Пароли сетей лежат в той же конфигурации, но мы их не трогаем. #>
    if ($script:Topology) { return $script:Topology }

    $d = Read-RouterConfig -Id $CFG_WIFI
    $t = @{}
    foreach ($b in $Bands) {
        $t[$b.Key] = [pscustomobject]@{
            Enabled  = [string]$d."$($b.Prefix)Radio" -in @("True", "1")
            Networks = [int]$d."$($b.Prefix)mbssidNum"
        }
    }
    $script:Topology = $t
    return $t
}

function Get-EnabledBands {
    <# Диапазоны, в которые вообще имеет смысл писать. #>
    $t = Get-WifiTopology
    return @($Bands | Where-Object { $t[$_.Key].Enabled })
}

function Get-SafeHostname([string]$Name) {
    # В поле hostname роутера кладём только латиницу и цифры: кириллица в
    # прошивке не проверялась, рисковать не будем.
    $clean = ($Name -replace '[^A-Za-z0-9_-]', '')
    if ($clean.Length -gt 20) { $clean = $clean.Substring(0, 20) }
    return $clean
}

function Get-Whitelist {
    <# Возвращает хэш: ключ диапазона -> список объектов {Name, Mac}. #>
    if (-not (Test-Path $WhitelistFile)) {
        throw "Не найден $WhitelistFile. Возьмите за образец whitelist.example.json."
    }
    $raw = Get-Content $WhitelistFile -Raw -Encoding UTF8 | ConvertFrom-Json

    $result = @{}
    foreach ($b in $Bands) { $result[$b.Key] = @() }

    foreach ($entry in @($raw)) {
        if (-not $entry.mac) { continue }
        $mac  = ConvertTo-RouterMac $entry.mac
        $name = if ($entry.name) { [string]$entry.name } else { '—' }
        $band = if ($entry.band) { [string]$entry.band } else { 'both' }

        foreach ($b in $Bands) {
            if ($band -eq 'both' -or $band -eq $b.Key) {
                $result[$b.Key] += [pscustomobject]@{ Name = $name; Mac = $mac }
            }
        }
    }
    return $result
}

function Get-WhitelistDevices($ByBand) {
    <#  Тот же белый список, но с точки зрения устройства, а не диапазона:
        имя, адрес и в каких диапазонах он разрешён.

        Перечислять содержимое каждого фильтра по отдельности сбивает с
        толку. Ноутбук с аппаратным адресом попадает в оба списка с одним и
        тем же адресом — и это выглядит ошибкой, хотя так и должно быть:
        адрес принадлежит адаптеру, а не сети. Телефон с рандомизацией,
        наоборот, приходит в каждую сеть со своим адресом и занимает две
        разные строки. Рядом эти два случая читаются понятно. #>

    $order = @()
    $byMac = @{}
    foreach ($b in $Bands) {
        foreach ($e in $ByBand[$b.Key]) {
            if (-not $byMac.ContainsKey($e.Mac)) {
                $byMac[$e.Mac] = [pscustomobject]@{ Name = $e.Name; Mac = $e.Mac; Bands = @() }
                $order += $e.Mac
            }
            $byMac[$e.Mac].Bands += $b.Key
        }
    }
    return @($order | ForEach-Object { $byMac[$_] } | Sort-Object Name)
}

function Get-BandState([string]$Prefix) {
    $d = Read-RouterConfig -Id $CFG_FILTER

    $policy = [int]$d."${Prefix}AccessPolicy"
    $listed = @()
    $listObj = $d."${Prefix}MacFilterList"
    if ($listObj) {
        foreach ($p in $listObj.PSObject.Properties) {
            if ($p.Name -eq 'max_instance') { continue }
            if ($p.Value.mac) {
                # Имя свойства — это позиция записи в списке. Она понадобится
                # для удаления, поэтому запоминаем её вместе с самой записью.
                $listed += [pscustomobject]@{
                    Mac    = ConvertTo-RouterMac $p.Value.mac
                    Host   = [string]$p.Value.hostname
                    Active = [bool]$p.Value.active
                    Pos    = [int]$p.Name
                    Raw    = $p.Value
                }
            }
        }
    }
    return [pscustomobject]@{ Policy = $policy; Rules = @($listed); MaxRules = [int]$d.MaxNumMacFilter }
}

function Get-PolicyTitle([int]$Policy) {
    switch ($Policy) {
        0 { 'выключен' }
        1 { 'ВКЛЮЧЁН — только из списка' }
        2 { 'чёрный список' }
        default { "неизвестно ($Policy)" }
    }
}

# Все три операции ниже идут с save=false: во флеш-память конфигурацию
# пишет одна команда в конце действия. Иначе каждое добавленное правило
# сохранялось бы отдельно — при включении списка это девять записей во
# флеш вместо одной. Обрыв на середине теперь оставляет изменения только
# в оперативной конфигурации, и перезагрузка их отменит.
#
# Диапазон задаётся префиксом поля для единственной сети в диапазоне.

function Add-BandRule([string]$Prefix, [string]$Mac, [string]$Name) {
    $rule = @{ mac = $Mac; hostname = (Get-SafeHostname $Name); active = $true }
    Write-RouterConfig -Id $CFG_FILTER -Data @{ "${Prefix}MacFilterList" = $rule } -Pos -1 -Save $false | Out-Null
}

function Remove-BandRule([string]$Prefix, [int]$Pos, $Entry) {
    # Удаляем ту же запись, что и читали: контейнер тот же, что при записи,
    # позиция — номер записи в списке.
    Remove-RouterConfig -Id $CFG_FILTER -Data @{ "${Prefix}MacFilterList" = $Entry } -Pos $Pos -Save $false | Out-Null
}

function Set-BandPolicy([string]$Prefix, [int]$Policy) {
    Write-RouterConfig -Id $CFG_FILTER -Data @{ "${Prefix}AccessPolicy" = $Policy } -Save $false | Out-Null
}

function Show-Message([string]$TextBody, [string]$Title, [string]$Icon) {
    if ($Text) { Write-Host $TextBody; return }
    Add-Type -AssemblyName System.Windows.Forms
    $ico = [System.Windows.Forms.MessageBoxIcon]::Information
    if ($Icon -eq 'warn')  { $ico = [System.Windows.Forms.MessageBoxIcon]::Warning }
    if ($Icon -eq 'error') { $ico = [System.Windows.Forms.MessageBoxIcon]::Error }
    [System.Windows.Forms.MessageBox]::Show($TextBody, $Title,
        [System.Windows.Forms.MessageBoxButtons]::OK, $ico) | Out-Null
}

function Confirm-Action([string]$TextBody, [string]$Title) {
    if ($NoConfirm) { return $true }
    if ($Text) {
        Write-Host $TextBody
        $answer = Read-Host 'Продолжить? (y/n)'
        return ($answer -match '^[yYдД]')
    }
    Add-Type -AssemblyName System.Windows.Forms
    $r = [System.Windows.Forms.MessageBox]::Show($TextBody, $Title,
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning)
    return ($r -eq [System.Windows.Forms.DialogResult]::Yes)
}

# ------------------------------------------------------------------- действия ---

function Invoke-Status {
    $topo = Get-WifiTopology
    Write-Host ''
    foreach ($b in $Bands) {
        if (-not $topo[$b.Key].Enabled) {
            Write-Host ("{0,-8} радио выключено — фильтр в этом диапазоне ни на что не влияет" -f $b.Title)
            Write-Host ''
            continue
        }
        if ($topo[$b.Key].Networks -gt 1) {
            Write-Host ("{0,-8} несколько сетей — фильтр смотрите в веб-интерфейсе" -f $b.Title)
            continue
        }
        $st = Get-BandState $b.Prefix
        Write-Host ("{0,-8} фильтр: {1}" -f $b.Title, (Get-PolicyTitle $st.Policy))
        if ($st.Rules.Count -eq 0) {
            Write-Host '         список пуст'
        } else {
            foreach ($r in $st.Rules) {
                $mark = if ($r.Active) { 'вкл' } else { 'выкл' }
                Write-Host ("         {0}  {1,-6} {2}" -f $r.Mac, $mark, $r.Host)
            }
        }
        Write-Host ''
    }
}

function Get-LiveRulesForChanges {
    $active = @(Get-EnabledBands)
    foreach ($band in $active) {
        if ((Get-WifiTopology)[$band.Key].Networks -ne 1) {
            throw 'Не удалось однозначно определить сеть. Измените белый список в веб-интерфейсе роутера.'
        }
    }
    $states = @{}
    foreach ($band in $active) { $states[$band.Key] = Get-BandState $band.Prefix }
    return $states
}

function Get-RuleState($Rules, [string]$Mac) {
    $found = @($Rules | Where-Object { $_.Mac -eq $Mac })
    if ($found.Count -gt 1) { throw "Для $Mac найдено несколько правил. Проверьте их в настройках роутера." }
    if ($found.Count -eq 0) { return 'none' }
    if ($found[0].Active) { return 'active' }
    return 'inactive'
}

function Invoke-ApplyWifiChanges($Edits, $States) {
    if (@($Edits).Count -eq 0) { return }
    $local = @(Get-LocalMacAddresses)
    $checked = @()
    $seen = @{}
    foreach ($edit in $Edits) {
        $band = $Bands | Where-Object { $_.Key -eq $edit.band } | Select-Object -First 1
        $mac = ConvertTo-RouterMac $edit.mac
        if (-not $band -or -not $States.ContainsKey($band.Key) -or $mac -notmatch '^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$' -or
            $edit.enabled -isnot [bool] -or $edit.expected -notin @('none','active','inactive')) {
            throw 'Некорректное изменение белого списка.'
        }
        $key = "$($band.Key):$mac"
        if ($seen.ContainsKey($key)) { throw 'Одно правило указано дважды.' }
        $seen[$key] = $true
        $state = $States[$band.Key]
        if ($state.Policy -eq $POLICY_DENY) { throw "В диапазоне $($band.Title) действует чёрный список." }
        if ($null -ne $edit.policy -and [int]$edit.policy -ne $state.Policy) {
            throw 'Политика Wi-Fi изменилась с момента открытия списка. Обновите окно.'
        }
        $actual = Get-RuleState $state.Rules $mac
        if ($actual -ne $edit.expected) { throw "Правило $mac изменилось с момента открытия списка. Обновите окно." }
        if (-not $Force -and -not $edit.enabled -and $state.Policy -eq $POLICY_ALLOW -and
            ($local.Count -eq 0 -or $local -contains $mac)) {
            throw 'Удаление может лишить этот компьютер доступа к роутеру.'
        }
        $want = if ($edit.enabled) { 'active' } else { 'none' }
        if ($want -ne $actual) {
            $checked += [pscustomobject]@{ Band=$band; Mac=$mac; Name=[string]$edit.name; Enabled=$edit.enabled;
                Expected=$actual; Wanted=$want }
        }
    }
    if ($checked.Count -eq 0) { return }

    foreach ($band in $Bands) {
        if (-not $States.ContainsKey($band.Key)) { continue }
        $bandEdits = @($checked | Where-Object { $_.Band.Key -eq $band.Key })
        if ($bandEdits.Count -eq 0) { continue }
        $state = $States[$band.Key]
        $activeMacs = @($state.Rules | Where-Object Active | ForEach-Object Mac)
        foreach ($edit in $bandEdits) {
            $activeMacs = @($activeMacs | Where-Object { $_ -ne $edit.Mac })
            if ($edit.Enabled) { $activeMacs += $edit.Mac }
        }
        if ($state.Policy -eq $POLICY_ALLOW -and $activeMacs.Count -eq 0 -and -not $Force) {
            throw "В действующем белом списке $($band.Title) должно остаться хотя бы одно устройство."
        }
    }

    foreach ($edit in ($checked | Sort-Object Enabled -Descending)) {
        $state = Get-BandState $edit.Band.Prefix
        if ($state.Policy -ne $States[$edit.Band.Key].Policy -or (Get-RuleState $state.Rules $edit.Mac) -ne $edit.Expected) {
            throw "Правило $($edit.Mac) изменилось. Обновите окно и проверьте результат."
        }
        $existing = $state.Rules | Where-Object { $_.Mac -eq $edit.Mac } | Select-Object -First 1
        if ($existing) {
            if (-not $Force -and -not $edit.Enabled -and $existing.Active -and $state.Policy -eq $POLICY_ALLOW -and
                @($state.Rules | Where-Object { $_.Active -and $_.Mac -ne $edit.Mac }).Count -eq 0) {
                throw 'Последнее устройство действующего белого списка удалить нельзя.'
            }
            Remove-BandRule $edit.Band.Prefix $existing.Pos $existing.Raw
        }
        if ($edit.Enabled) { Add-BandRule $edit.Band.Prefix $edit.Mac $edit.Name }
    }

    $verified = Get-LiveRulesForChanges
    foreach ($edit in $checked) {
        if (-not $verified.ContainsKey($edit.Band.Key) -or
            (Get-RuleState $verified[$edit.Band.Key].Rules $edit.Mac) -ne $edit.Wanted) {
            throw 'Роутер показал другой результат. Обновите окно перед повтором.'
        }
    }
    Save-RouterConfig | Out-Null
    Show-Message "Правила проверены и сохранены. Изменений: $($checked.Count)." 'Белый список Wi-Fi' 'info'
}

function Invoke-PolicyFromRouter([int]$Policy) {
    $before = Get-LiveRulesForChanges
    $targets = @($Bands | Where-Object { $before.ContainsKey($_.Key) -and $before[$_.Key].Policy -ne $Policy })
    if ($targets.Count -eq 0) { return }
    $local = @(Get-LocalMacAddresses)
    $lines = @()
    foreach ($band in $targets) {
        $state = $before[$band.Key]
        if ($state.Policy -eq $POLICY_DENY) { throw "В диапазоне $($band.Title) действует чёрный список." }
        $allow = @($state.Rules | Where-Object Active | ForEach-Object Mac)
        if ($Policy -eq $POLICY_ALLOW -and -not $Force -and
            ($allow.Count -eq 0 -or @($allow | Where-Object { $local -contains $_ }).Count -eq 0)) {
            throw "Добавьте MAC этого компьютера в белый список $($band.Title)."
        }
        $lines += "$($band.Title): $(Get-PolicyTitle $Policy)"
        if ($Policy -eq $POLICY_ALLOW) { $lines += @($allow | Sort-Object) }
    }
    if (-not (Confirm-Action ($lines -join "`n") 'Изменить режим Wi-Fi?')) { return }
    $fresh = Get-LiveRulesForChanges
    foreach ($band in $targets) {
        if (-not $fresh.ContainsKey($band.Key)) { throw 'Состав сетей изменился. Обновите окно.' }
        $state = $fresh[$band.Key]
        $expected = @($before[$band.Key].Rules | Where-Object Active | ForEach-Object Mac | Sort-Object) -join ' '
        $actual = @($state.Rules | Where-Object Active | ForEach-Object Mac | Sort-Object) -join ' '
        if ($state.Policy -ne $before[$band.Key].Policy -or $actual -ne $expected) { throw 'Правила Wi-Fi изменились. Обновите окно.' }
    }
    foreach ($band in $targets) {
        Set-BandPolicy $band.Prefix $Policy
        if ((Get-BandState $band.Prefix).Policy -ne $Policy) { throw "Роутер не подтвердил политику $($band.Title)." }
    }
    Save-RouterConfig | Out-Null
    Show-Message 'Политика Wi-Fi проверена и сохранена.' 'Белый список Wi-Fi' 'info'
}

function Invoke-Sync {
    $states = Get-LiveRulesForChanges
    $file = Get-Whitelist
    $edits = @()
    foreach ($band in $Bands) {
        if (-not $states.ContainsKey($band.Key)) { continue }
        foreach ($entry in $file[$band.Key]) {
            $before = Get-RuleState $states[$band.Key].Rules $entry.Mac
            if ($before -ne 'active') {
                $edits += [pscustomobject]@{ band=$band.Key; mac=$entry.Mac; name=$entry.Name; enabled=$true; expected=$before;
                    policy=$states[$band.Key].Policy }
            }
        }
    }
    if ($edits.Count -eq 0) { return }
    $lines = $edits | ForEach-Object { "Добавить $($_.mac) · $($_.band) ГГц" }
    if (Confirm-Action ($lines -join "`n") 'Импорт из whitelist.json') { Invoke-ApplyWifiChanges $edits $states }
}


# ---------------------------------------------------------------------- запуск ---

try {
    switch ($Action) {
        'status' { Invoke-Status }
        'on'     { Invoke-PolicyFromRouter $POLICY_ALLOW }
        'off'    { Invoke-PolicyFromRouter $POLICY_OFF }
        'sync'   { Invoke-Sync }
        'patch'  { Invoke-ApplyWifiChanges $Changes (Get-LiveRulesForChanges) }
    }
}
catch {
    if ($Text -or $Action -eq 'status') { throw }
    Show-Message $_.Exception.Message 'Белый список Wi-Fi — ошибка' 'error'
    exit 1
}
