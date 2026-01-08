<#
.SYNOPSIS
    Windows 11 systems must use a BitLocker PIN with a minimum length of six digits for pre-boot authentication.

.NOTES
    Author          : Imran (Ian) Huhn
    LinkedIn        : linkedin.com/in/ianhuhntech
    GitHub          : github.com/IanImranHuhn
    Date Created    : 2026-01-07
    Last Modified   : 2026-01-08
    Version         : 1.1
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-00-000032
    STIGaview Link  : https://stigaview.com/products/win11/v2r5/WN11-00-000032/

.TESTED ON
    Date(s) Tested  : 2026-01-07, 2026-01-08
    Tested By       : Imran (Ian) Huhn
    Systems Tested  : Windows 11 Pro (22H2)
    PowerShell Ver. : 5.1.26100.7462 

.USAGE
    Run this script in an elevated PowerShell session:
        PS C:\> .\WN11-00-000032.ps1 
#>

$RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
$ValueName    = "MinimumPIN"
$MinimumValue = 6
$CurrentValue = Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue

function Test-IsVirtualDesktop {
    $IsAVD = Test-Path "HKLM:\SOFTWARE\Microsoft\RDInfra"
    $IsVM  = (Get-CimInstance Win32_ComputerSystem).Model -match "Virtual Machine|VMware|Hyper-V"
    
    return $IsAVD -or $IsVM
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as an Administrator."
    exit
}

if (Test-IsVirtualDesktop) {
    Write-Host "[INFO] This machine appears to be a Virtual Desktop/AVD instance." -ForegroundColor Cyan
    Write-Host "[INFO] If this instance is non-persistent or has no data at rest, this requirement is NA." -ForegroundColor Cyan
}

if (-not (Test-Path $RegistryPath)) {
    Write-Host "Creating missing registry path: $RegistryPath" -ForegroundColor Yellow
    New-Item -Path $RegistryPath -Force | Out-Null
}

if ($null -eq $CurrentValue) {
    Write-Host "$ValueName is missing. Setting to $MinimumValue." -ForegroundColor Red
    New-ItemProperty -Path $RegistryPath -Name $ValueName -Value $MinimumValue -PropertyType DWord -Force | Out-Null
} elseif ($CurrentValue.$ValueName -lt $MinimumValue) {
    Write-Host "Current $ValueName is $($CurrentValue.$ValueName), which is less than $MinimumValue. Updating..." -ForegroundColor Yellow
    Set-ItemProperty -Path $RegistryPath -Name $ValueName -Value $MinimumValue -Force
} else {
    Write-Host "$ValueName is already compliant ($($CurrentValue.$ValueName)). No action needed." -ForegroundColor Green
}

Write-Host "Remediation complete." -ForegroundColor White