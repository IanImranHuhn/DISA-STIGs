<#
.SYNOPSIS
    IPv6 source routing must be configured to highest protection.

.NOTES
    Author          : Imran (Ian) Huhn
    LinkedIn        : linkedin.com/in/ianhuhntech
    GitHub          : github.com/IanImranHuhn
    Date Created    : 2026-01-07
    Last Modified   : 2026-01-08
    Version         : 1.1
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000020
    STIGaview Link  : https://stigaview.com/products/win11/v2r5/WN11-CC-000020/
    
.TESTED ON
    Date(s) Tested  : 2026-01-07, 2026-01-08
    Tested By       : Imran (Ian) Huhn
    Systems Tested  : Windows 11 Pro (22H2)
    PowerShell Ver. : 5.1.26100.7462 

.USAGE
    Run this script in an elevated PowerShell session:
        PS C:\> .\WN11-CC-000020.ps1 
#>

$RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
$ValueName    = "DisableIpSourceRouting"
$DesiredValue = 2
$CurrentValue = Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as an Administrator."
    exit
}

if (-not (Test-Path $RegistryPath)) {
    Write-Host "Creating missing registry path: $RegistryPath" -ForegroundColor Yellow
    New-Item -Path $RegistryPath -Force | Out-Null
}


if ($null -eq $CurrentValue) {
    Write-Host "$ValueName is missing. Setting to $DesiredValue (Source Routing Disabled)." -ForegroundColor Red
    New-ItemProperty -Path $RegistryPath -Name $ValueName -Value $DesiredValue -PropertyType DWord -Force | Out-Null
} elseif ($CurrentValue.$ValueName -ne $DesiredValue) {
    Write-Host "Current $ValueName is $($CurrentValue.$ValueName). Updating to $DesiredValue..." -ForegroundColor Yellow
    Set-ItemProperty -Path $RegistryPath -Name $ValueName -Value $DesiredValue -Force
} else {
    Write-Host "IPv6 Source Routing is already correctly configured ($ValueName = $DesiredValue)." -ForegroundColor Green
}

Write-Host "Remediation complete." -ForegroundColor White