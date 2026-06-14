# Скрипт выполняет базовый аудит безопасности Windows и выявляет потенциально опасные настройки и объекты системы. Он анализирует записи автозагрузки, состояние UAC и брандмауэра, установленные программы, службы, драйверы и задачи планировщика, отмечая подозрительные элементы по набору правил и сигнатур. Обнаруженные события записываются в журнал system_monitor.log с указанием времени. Скрипт предназначен для автоматизированной проверки системы и может использоваться в качестве вспомогательного инструмента при администрировании и мониторинге безопасности.

# ========== НАСТРОЙКИ ==========
$logPath = "C:\RegSecurity\system_monitor.log"
$blacklist = @("uTorrent", "TeamViewer", "Anydesk", "KMSpico", "Cheat Engine")
$autorunKeys = @(
  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
)
$uninstallKeys = @(
  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
  "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

# ========== ЛОГ ФУНКЦИЯ ==========
function Log($msg) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content $logPath "$timestamp - $msg"
}

# ========== 1. Анализ автозагрузки ==========
foreach ($key in $autorunKeys) {
    try {
        $values = Get-ItemProperty -Path $key
        foreach ($name in $values.PSObject.Properties.Name) {
            $data = $values.$name
            if ($data -match "cmd\.exe|powershell|wscript|mshta|\.vbs|http") {
                Log "ПОДОЗРИТЕЛЬНАЯ АВТОЗАГРУЗКА: $key\$name = $data"
            }
        }
    } catch {}
}

# ========== 2. Проверка UAC ==========
try {
    $uac = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"
    if ($uac -ne 1) {
        Log "ВНИМАНИЕ: UAC отключен!"
    }
} catch {}

# ========== 3. Проверка Брандмауэра ==========
try {
    $fw = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" -Name "EnableFirewall"
    if ($fw -ne 1) {
        Log "ВНИМАНИЕ: Брандмауэр отключен!"
    }
} catch {}

# ========== 4. Поиск запрещённых программ ==========
foreach ($path in $uninstallKeys) {
    try {
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
            $name = $_.DisplayName
            if ($name) {
                foreach ($bad in $blacklist) {
                    if ($name -like "*$bad*") {
                        Log "ЗАПРЕЩЁННАЯ ПРОГРАММА: $name"
                    }
                }
            }
        }
    } catch {}
}

# ========== 5. Проверка подозрительных служб ==========
try {
    Get-CimInstance Win32_Service | Where-Object {
        $_.StartMode -in @("Auto", "Boot") -and
        $_.PathName -match "\\Users\\|AppData|Temp|\.exe" -and
        $_.State -eq "Running"
    } | ForEach-Object {
        Log "ПОДОЗРИТЕЛЬНАЯ СЛУЖБА: $($_.Name) - $($_.PathName)"
    }
} catch {}

# ========== 6. Проверка подозрительных драйверов ==========
try {
    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\*" | Where-Object {
        $_.Type -eq 1 -and $_.Start -le 2 -and $_.ImagePath -match "Users|AppData|Temp|\.exe|\.sys"
    } | ForEach-Object {
        Log "ПОДОЗРИТЕЛЬНЫЙ ДРАЙВЕР: $($_.PSChildName) - $($_.ImagePath)"
    }
} catch {}

# ========== 7. Проверка задач планировщика ==========
try {
    $tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" }
    foreach ($task in $tasks) {
        $actions = ($task.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }) -join " "
        if ($actions -match "cmd\.exe|powershell|wscript|mshta|http") {
            Log "ПОДОЗРИТЕЛЬНАЯ ЗАДАЧА: $($task.TaskName) - $actions"
        }
    }
} catch {}

# ========== Завершение ==========
Log "Проверка завершена."
