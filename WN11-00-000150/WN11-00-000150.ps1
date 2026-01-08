<#
.SYNOPSIS
    Structured Exception Handling Overwrite Protection (SEHOP) must be enabled.

.NOTES
    Author          : Imran (Ian) Huhn
    LinkedIn        : linkedin.com/in/ianhuhntech
    GitHub          : github.com/IanImranHuhn
    Date Created    : 2026-01-07
    Last Modified   : 2026-01-08
    Version         : 1.1
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-00-000150
    STIGaview Link  : https://stigaview.com/products/win11/v2r5/WN11-00-000150/

.TESTED ON
    Date(s) Tested  : 2026-01-07, 2026-01-08
    Tested By       : Imran (Ian) Huhn
    Systems Tested  : Windows 11 Pro (22H2)
    PowerShell Ver. : 5.1.26100.7462 

.USAGE
    Run this script in an elevated PowerShell session:
        PS C:\> .\WN11-00-000150.ps1 
#>

$RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
$ValueName    = "DisableExceptionChainValidation"
$DesiredValue = 0
$CurrentValue = Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as an Administrator."
    exit
}

if (-not (Test-Path $RegistryPath)) {
    Write-Host "Creating missing registry path: $RegistryPath" -ForegroundColor Cyan
    New-Item -Path $RegistryPath -Force | Out-Null
}

if ($null -eq $CurrentValue) {
    Write-Host "$ValueName is missing. Setting to $DesiredValue (SEHOP Enabled)." -ForegroundColor Yellow
    New-ItemProperty -Path $RegistryPath -Name $ValueName -Value $DesiredValue -PropertyType DWord -Force | Out-Null
} elseif ($CurrentValue.$ValueName -ne $DesiredValue) {
    Write-Host "Current $ValueName is $($CurrentValue.$ValueName). Updating to $DesiredValue..." -ForegroundColor Red
    Set-ItemProperty -Path $RegistryPath -Name $ValueName -Value $DesiredValue -Force
} else {
    Write-Host "SEHOP is already correctly configured ($ValueName = $DesiredValue)." -ForegroundColor Green
}

Write-Host "Remediation complete." -ForegroundColor White