# Скрипт выполняет аудит параметров безопасности Windows и собирает сведения о потенциально подозрительных элементах системы. В ходе проверки анализируются записи автозагрузки, настройки UAC и брандмауэра, установленные программы, службы, драйверы и запланированные задачи, а обнаруженные события сохраняются в журнал. Для получения информации используются механизмы реестра Windows, WMI и интерфейсы планировщика задач. Инструмент предназначен для мониторинга состояния системы, выявления нежелательных изменений конфигурации и изучения методов инвентаризации компонентов Windows.


import winreg
import os
import datetime
import subprocess
import win32com.client
import win32serviceutil
import win32service
import wmi

LOG_PATH = "C:\\RegSecurity\\system_monitor.log"
BLACKLIST = ["uTorrent", "TeamViewer", "Anydesk", "KMSpico", "Cheat Engine"]
AUTORUN_PATHS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run")
]
UNINSTALL_PATHS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
]

def log(msg):
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"{ts} - {msg}\n")

def check_autorun():
    for root, path in AUTORUN_PATHS:
        try:
            with winreg.OpenKey(root, path) as key:
                for i in range(winreg.QueryInfoKey(key)[1]):
                    name, value, _ = winreg.EnumValue(key, i)
                    if any(s in value.lower() for s in ['powershell', 'cmd.exe', 'wscript', 'mshta', '.vbs', 'http']):
                        log(f"ПОДОЗРИТЕЛЬНАЯ АВТОЗАГРУЗКА: {path}\\{name} = {value}")
        except FileNotFoundError:
            continue

def check_uac():
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            value, _ = winreg.QueryValueEx(key, "EnableLUA")
            if value != 1:
                log("ВНИМАНИЕ: UAC отключен!")
    except Exception:
        pass

def check_firewall():
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile") as key:
            value, _ = winreg.QueryValueEx(key, "EnableFirewall")
            if value != 1:
                log("ВНИМАНИЕ: Брандмауэр отключен!")
    except Exception:
        pass

def check_blacklisted_programs():
    for root, path in UNINSTALL_PATHS:
        try:
            with winreg.OpenKey(root, path) as key:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name) as subkey:
                            name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                            if any(bad.lower() in name.lower() for bad in BLACKLIST):
                                log(f"ЗАПРЕЩЁННАЯ ПРОГРАММА: {name}")
                    except Exception:
                        continue
        except Exception:
            continue

def check_services():
    c = wmi.WMI()
    for s in c.Win32_Service():
        if s.StartMode in ["Auto", "Boot"] and s.State == "Running":
            if s.PathName and any(p in s.PathName for p in ["\\Users\\", "AppData", "Temp", ".exe"]):
                log(f"ПОДОЗРИТЕЛЬНАЯ СЛУЖБА: {s.Name} - {s.PathName}")

def check_drivers():
    c = wmi.WMI()
    for s in c.Win32_SystemDriver():
        if s.StartMode in ["Auto", "Boot"]:
            if s.PathName and any(p in s.PathName for p in ["Users", "AppData", "Temp", ".exe", ".sys"]):
                log(f"ПОДОЗРИТЕЛЬНЫЙ ДРАЙВЕР: {s.Name} - {s.PathName}")

def check_scheduled_tasks():
    scheduler = win32com.client.Dispatch("Schedule.Service")
    scheduler.Connect()
    rootFolder = scheduler.GetFolder("\\")
    tasks = rootFolder.GetTasks(1)

    for task in tasks:
        try:
            definition = task.Definition
            for action in definition.Actions:
                cmd = (action.Path + " " + action.Arguments).lower()
                if any(s in cmd for s in ["cmd.exe", "powershell", "wscript", "mshta", "http"]):
                    log(f"ПОДОЗРИТЕЛЬНАЯ ЗАДАЧА: {task.Name} - {cmd}")
        except Exception:
            continue

if __name__ == "__main__":
    check_autorun()
    check_uac()
    check_firewall()
    check_blacklisted_programs()
    check_services()
    check_drivers()
    check_scheduled_tasks()
    log("Проверка завершена.")
