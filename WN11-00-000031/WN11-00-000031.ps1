<#
.SYNOPSIS
    Windows 11 systems must use a BitLocker PIN for pre-boot authentication.

.NOTES
    Author          : Imran (Ian) Huhn
    LinkedIn        : linkedin.com/in/ianhuhntech
    GitHub          : github.com/IanImranHuhn
    Date Created    : 2026-01-07
    Last Modified   : 2026-01-08
    Version         : 1.1
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-00-000031
    STIGaview Link  : https://stigaview.com/products/win11/v2r5/WN11-00-000031/

.TESTED ON
    Date(s) Tested  : 2026-01-07, 2026-01-08
    Tested By       : Imran (Ian) Huhn
    Systems Tested  : Windows 11 Pro (22H2)
    PowerShell Ver. : 5.1.26100.7462 

.USAGE
    Run this script in an elevated PowerShell session:
        PS C:\> .\WN11-00-000031.ps1 
#>

$RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
$Settings = @{
    "UseAdvancedStartup" = 1
    "UseTPMPIN"          = 1
    "UseTPMKeyPIN"       = 1
}

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
    Write-Host "Creating missing registry path: $RegistryPath" -ForegroundColor Cyan
    New-Item -Path $RegistryPath -Force | Out-Null
}

foreach ($ValueName in $Settings.Keys) {
    $TargetValue = $Settings[$ValueName]
    $CurrentValue = Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue

    if ($null -eq $CurrentValue -or $CurrentValue.$ValueName -ne $TargetValue) {
        Write-Host "Setting $ValueName to $TargetValue..." -ForegroundColor Yellow
        Set-ItemProperty -Path $RegistryPath -Name $ValueName -Value $TargetValue -Type DWord -Force
    }
    else {
        Write-Host "$ValueName is already correctly configured as $TargetValue." -ForegroundColor Green
    }
}

Write-Host "Remediation complete." -ForegroundColor White