<#
.SYNOPSIS
    The display of slide shows on the lock screen must be disabled.

.NOTES
    Author          : Imran (Ian) Huhn
    LinkedIn        : linkedin.com/in/ianhuhntech
    GitHub          : github.com/IanImranHuhn
    Date Created    : 2026-01-07
    Last Modified   : 2026-01-08
    Version         : 1.1
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000010
    STIGaview Link  : https://stigaview.com/products/win11/v2r5/WN11-CC-000010/

.TESTED ON
    Date(s) Tested  : 2026-01-07, 2026-01-08
    Tested By       : Imran (Ian) Huhn
    Systems Tested  : Windows 11 Pro (22H2)
    PowerShell Ver. : 5.1.26100.7462 

.USAGE
    Run this script in an elevated PowerShell session:
        PS C:\> .\WN11-CC-000010.ps1 
#>

$RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
$ValueName    = "NoLockScreenSlideshow"
$DesiredValue = 1
$CurrentValue = Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as an Administrator."
    exit
}

if (-not (Test-Path $RegistryPath)) {
    Write-Host "Creating missing registry path: $RegistryPath" -ForegroundColor Yellow
    New-Item -Path $RegistryPath -Force | Out-Null
}


if ($null -eq $CurrentValue -or $CurrentValue.$ValueName -ne $DesiredValue) {
    Write-Host "Remediating $ValueName. Setting value to $DesiredValue..." -ForegroundColor Red
    Set-ItemProperty -Path $RegistryPath -Name $ValueName -Value $DesiredValue -Type DWord -Force
} else {
    Write-Host "The lock screen slideshow is already correctly disabled ($ValueName = 1)." -ForegroundColor Green
}

Write-Host "Remediation complete." -ForegroundColor White