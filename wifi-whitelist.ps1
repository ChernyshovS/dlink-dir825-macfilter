<#
.SYNOPSIS
    Белый список Wi-Fi: оставить доступ только заранее заданным устройствам.

.DESCRIPTION
    Управляет MAC-фильтром беспроводных сетей роутера D-Link DIR-825ACG1.
    В режиме «включено» к Wi-Fi могут подключиться только устройства из
    whitelist.json, остальные не проходят авторизацию на точке доступа.

    Проводные подключения этот фильтр НЕ затрагивает — устройства на LAN-портах
    продолжают работать. Ими управляет отдельный скрипт dlink-macfilter.ps1.

    Настройки Wi-Fi (имена сетей, пароли, каналы) не читаются и не изменяются:
    фильтр живёт в отдельной конфигурации роутера.

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
    [ValidateSet('status', 'on', 'off', 'sync')]
    [string]$Action = 'status',

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

$CFG_CURSOR = 39   # выбор сети, для которой выполняется операция
$CFG_FILTER = 42   # политика доступа и списки MAC-адресов

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

function Set-BandCursor([string]$Prefix) {
    # Курсор выбирает сеть внутри диапазона. Сеть у нас одна, поэтому всегда 1.
    # save=$false: значение служебное, во флеш-память его писать незачем.
    Write-RouterConfig -Id $CFG_CURSOR -Data @{ "${Prefix}mbssidCur" = 1 } -Save $false | Out-Null
}

function Get-BandState([string]$Prefix) {
    Set-BandCursor $Prefix
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

function Add-BandRule([string]$Prefix, [string]$Mac, [string]$Name) {
    Set-BandCursor $Prefix
    $rule = @{ mac = $Mac; hostname = (Get-SafeHostname $Name); active = $true }
    Write-RouterConfig -Id $CFG_FILTER -Data @{ "${Prefix}MacFilterList" = $rule } -Pos -1 | Out-Null
}

function Remove-BandRule([string]$Prefix, [int]$Pos, $Entry) {
    # Удаляем ту же запись, что и читали: контейнер тот же, что при записи,
    # позиция — номер записи в списке.
    Set-BandCursor $Prefix
    Remove-RouterConfig -Id $CFG_FILTER -Data @{ "${Prefix}MacFilterList" = $Entry } -Pos $Pos | Out-Null
}

function Set-BandPolicy([string]$Prefix, [int]$Policy) {
    Set-BandCursor $Prefix
    Write-RouterConfig -Id $CFG_FILTER -Data @{ "${Prefix}AccessPolicy" = $Policy } | Out-Null
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
    Write-Host ''
    foreach ($b in $Bands) {
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

function Invoke-Enable {
    $wl = Get-Whitelist
    $localMacs = Get-LocalMacAddresses

    # --- проверки до любой записи ---------------------------------------
    foreach ($b in $Bands) {
        if ($wl[$b.Key].Count -eq 0 -and -not $Force) {
            throw ("Для диапазона $($b.Title) белый список пуст. Включение отрезало бы " +
                   "от Wi-Fi все устройства в этом диапазоне. Дополните whitelist.json.")
        }
    }

    $allMacs = @()
    foreach ($b in $Bands) { $allMacs += $wl[$b.Key].Mac }
    $selfPresent = @($allMacs | Where-Object { $localMacs -contains $_ }).Count -gt 0

    if (-not $selfPresent -and -not $Force) {
        throw ("В белом списке нет ни одного сетевого адаптера этого компьютера. " +
               "После включения вы потеряете и Wi-Fi, и доступ к роутеру. " +
               "Добавьте свой адрес в whitelist.json или запустите с ключом -Force.")
    }

    $warnings = @()
    foreach ($b in $Bands) {
        $hasSelf = @($wl[$b.Key].Mac | Where-Object { $localMacs -contains $_ }).Count -gt 0
        if (-not $hasSelf) {
            $warnings += "В диапазоне $($b.Title) нет адреса этого компьютера — подключившись к нему, вы потеряете управление."
        }
    }

    # --- подтверждение ---------------------------------------------------
    $lines = @('После включения доступ к Wi-Fi сохранят только эти устройства:', '')
    foreach ($b in $Bands) {
        $lines += "  $($b.Title):"
        foreach ($e in $wl[$b.Key]) { $lines += "     $($e.Mac)   $($e.Name)" }
    }
    $lines += ''
    $lines += 'Все остальные устройства не смогут подключиться к Wi-Fi.'
    $lines += 'Проводные подключения не затрагиваются.'
    if ($warnings.Count -gt 0) { $lines += ''; $lines += $warnings }
    $lines += ''
    $lines += 'Включить белый список?'

    if (-not (Confirm-Action ($lines -join [Environment]::NewLine) 'Белый список Wi-Fi')) {
        Show-Message 'Отменено, ничего не изменено.' 'Белый список Wi-Fi' 'info'
        return
    }

    # --- этап 1: наполняем списки (политика ещё выключена) ---------------
    $added = 0
    foreach ($b in $Bands) {
        $st = Get-BandState $b.Prefix
        if ($st.MaxRules -gt 0 -and $wl[$b.Key].Count -gt $st.MaxRules) {
            throw "В диапазоне $($b.Title) роутер принимает не более $($st.MaxRules) адресов, а в списке $($wl[$b.Key].Count)."
        }
        $existing = @($st.Rules.Mac)
        foreach ($e in $wl[$b.Key]) {
            if ($existing -notcontains $e.Mac) {
                Add-BandRule $b.Prefix $e.Mac $e.Name
                $added++
            }
        }
    }

    # --- этап 2: включаем политику последней командой --------------------
    foreach ($b in $Bands) { Set-BandPolicy $b.Prefix $POLICY_ALLOW }

    # --- проверка результата ---------------------------------------------
    $report = @('Белый список включён.', '')
    foreach ($b in $Bands) {
        $st = Get-BandState $b.Prefix
        $report += "$($b.Title): $(Get-PolicyTitle $st.Policy), адресов в списке: $($st.Rules.Count)"
    }
    $report += ''
    $report += "Добавлено новых записей: $added"
    Show-Message ($report -join [Environment]::NewLine) 'Белый список Wi-Fi' 'info'
}

function Invoke-Sync {
    <#  Приводит списки на роутере в соответствие с whitelist.json: лишние
        адреса удаляет, недостающие добавляет. Политику доступа не трогает —
        включение и выключение остаются отдельными действиями.

        Нужно потому, что «включить» умеет только добавлять. Без удаления
        вычеркнутое из файла устройство сохраняло бы доступ к Wi-Fi, и файл
        перестал бы быть единственным источником правды. #>

    $wl        = Get-Whitelist
    $localMacs = Get-LocalMacAddresses

    # --- проверка до любой записи ----------------------------------------
    foreach ($b in $Bands) {
        $st   = Get-BandState $b.Prefix
        $want = @($wl[$b.Key].Mac)
        if ($st.Policy -eq $POLICY_ALLOW -and -not $Force) {
            $losing = @($st.Rules | Where-Object { $want -notcontains $_.Mac -and $localMacs -contains $_.Mac })
            if ($losing.Count -gt 0) {
                throw ("В диапазоне $($b.Title) синхронизация удалила бы адрес этого компьютера " +
                       "($($losing[0].Mac)), а белый список сейчас включён — доступ к роутеру пропал бы " +
                       "сразу. Верните адрес в whitelist.json или запустите с ключом -Force.")
            }
        }
    }

    # --- удаление лишних, затем добавление недостающих --------------------
    $removed = 0
    $added   = 0
    foreach ($b in $Bands) {
        $st   = Get-BandState $b.Prefix
        $want = @($wl[$b.Key].Mac)

        # Номера позиций устойчивы: удаление одной записи не сдвигает
        # остальные, так что порядок не важен. С конца — просто на случай,
        # если другая прошивка поведёт себя иначе.
        $extra = @($st.Rules | Where-Object { $want -notcontains $_.Mac } | Sort-Object Pos -Descending)
        foreach ($e in $extra) {
            Remove-BandRule $b.Prefix $e.Pos $e.Raw
            $removed++
        }

        $have = @((Get-BandState $b.Prefix).Rules.Mac)
        foreach ($e in $wl[$b.Key]) {
            if ($have -notcontains $e.Mac) {
                Add-BandRule $b.Prefix $e.Mac $e.Name
                $added++
            }
        }
    }

    # --- отчёт по тому, что реально лежит на роутере ----------------------
    $report = @('Списки на роутере приведены в соответствие с whitelist.json.', '')
    foreach ($b in $Bands) {
        $st = Get-BandState $b.Prefix
        $report += "$($b.Title): записей $($st.Rules.Count), фильтр — $(Get-PolicyTitle $st.Policy)"
        foreach ($r in $st.Rules) { $report += "     $($r.Mac)   $($r.Host)" }
        $report += ''
    }
    $report += "Удалено: $removed, добавлено: $added"
    Show-Message ($report -join [Environment]::NewLine) 'Белый список Wi-Fi' 'info'
}

function Invoke-Disable {
    foreach ($b in $Bands) { Set-BandPolicy $b.Prefix $POLICY_OFF }

    $report = @('Белый список выключен, Wi-Fi открыт для всех устройств.', '')
    foreach ($b in $Bands) {
        $st = Get-BandState $b.Prefix
        $report += "$($b.Title): $(Get-PolicyTitle $st.Policy), записей сохранено: $($st.Rules.Count)"
    }
    $report += ''
    $report += 'Список адресов сохранён — повторное включение будет быстрым.'
    Show-Message ($report -join [Environment]::NewLine) 'Белый список Wi-Fi' 'info'
}

# ---------------------------------------------------------------------- запуск ---

try {
    switch ($Action) {
        'status' { Invoke-Status }
        'on'     { Invoke-Enable }
        'off'    { Invoke-Disable }
        'sync'   { Invoke-Sync }
    }
    # Даже чтение сдвигает служебный курсор выбора сети. Без этой команды
    # роутер считает конфигурацию изменённой и просит сохранить её вручную.
    Save-RouterConfig | Out-Null
}
catch {
    if ($Text -or $Action -eq 'status') { throw }
    Show-Message $_.Exception.Message 'Белый список Wi-Fi — ошибка' 'error'
    exit 1
}
