#Requires -Version 5.1
<#
.SYNOPSIS
    Запуск экспортов DLL по ординалам через rundll32 с обходом крашей и блокировок.
#>

[CmdletBinding()]
param(
    [string] $DllPath        = "$PSScriptRoot\mydll.dll",
    [int]    $StartOrdinal   = 1,
    [int]    $EndOrdinal     = 20,
    [int]    $TimeoutSeconds = 5,
    [string] $LogFile        = "C:\Temp\dllrunner_log.txt"
)

if (-not (Test-Path $DllPath)) {
    Write-Error "DLL not found: $DllPath"; exit 1
}
$DllPath = (Resolve-Path $DllPath).Path

$logDir = Split-Path $LogFile -Parent
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}
if (Test-Path $LogFile) { Remove-Item $LogFile -Force }

Write-Host "=== DllRunner ===" -ForegroundColor Cyan
Write-Host "DLL      : $DllPath"
Write-Host "Ordinals : $StartOrdinal .. $EndOrdinal"
Write-Host "Timeout  : $TimeoutSeconds s"
Write-Host "Log      : $LogFile"
Write-Host ""

function Get-LogLines {
    param([string]$Path)
    if (Test-Path $Path) {
        return @(Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue)
    }
    return @()
}

$summary = @()

for ($ord = $StartOrdinal; $ord -le $EndOrdinal; $ord++) {

    $before = Get-LogLines $LogFile

    Write-Host ("[{0,2}] ord #{0,-2} " -f $ord) -NoNewline -ForegroundColor Cyan

    $status  = "OK"
    $details = ""
    $proc    = $null

    try {
        $proc = Start-Process -FilePath "rundll32.exe" `
                              -ArgumentList "`"$DllPath`",#$ord" `
                              -PassThru `
                              -WindowStyle Hidden `
                              -ErrorAction Stop

        if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
            $status  = "TIMEOUT"
            $details = "killed after $TimeoutSeconds s"
            try { Stop-Process -Id $proc.Id -Force -ErrorAction Stop } catch { }
            Start-Sleep -Milliseconds 400
        }
        else {
            $code = $null
            try { $code = $proc.ExitCode } catch { }

            if ($code -ne 0 -and $null -ne $code) {
                $status  = "CRASH"
                $details = ("exit code 0x{0:X8}" -f $code)
            }
        }
    }
    catch {
        $status  = "ERROR"
        $details = $_.Exception.Message
    }
    finally {
        if ($proc -and -not $proc.HasExited) {
            try { $proc.Kill() } catch { }
        }
    }

    Start-Sleep -Milliseconds 150
    $after = Get-LogLines $LogFile
    $new   = @($after | Select-Object -Skip $before.Count)

    $color = switch ($status) {
        "OK"      { "Green"  }
        "TIMEOUT" { "Yellow" }
        "CRASH"   { "Red"    }
        default   { "Magenta"}
    }
    if ($status -eq "OK") {
        Write-Host "OK" -ForegroundColor $color
    } else {
        Write-Host ("{0} ({1})" -f $status, $details) -ForegroundColor $color
    }

    foreach ($ln in $new) {
        Write-Host "        $ln" -ForegroundColor DarkGray
    }

    $summary += [pscustomobject]@{
        Ordinal = $ord
        Status  = $status
        Details = $details
        Lines   = $new.Count
    }

    Start-Sleep -Milliseconds 100
}

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
$summary | Format-Table -AutoSize

Write-Host "=== Full log ===" -ForegroundColor Cyan
if (Test-Path $LogFile) {
    Get-Content -LiteralPath $LogFile
} else {
    Write-Host "(no log written)"
}
