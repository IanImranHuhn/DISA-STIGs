<#
.SYNOPSIS
    The Application event log size must be configured to 32768 KB or greater.

.NOTES
    Author          : Imran (Ian) Huhn
    LinkedIn        : linkedin.com/in/ianhuhntech
    GitHub          : github.com/IanImranHuhn
    Date Created    : 2026-01-07
    Last Modified   : 2026-01-08
    Version         : 1.1
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000500
    STIGaview Link  : https://stigaview.com/products/win11/v2r5/WN11-AU-000500/

.TESTED ON
    Date(s) Tested  : 2026-01-07, 2026-01-08
    Tested By       : Imran (Ian) Huhn
    Systems Tested  : Windows 11 Pro (22H2)
    PowerShell Ver. : 5.1.26100.7462 

.USAGE
    Run this script in an elevated PowerShell session:
        PS C:\> .\WN11-AU-000500.ps1 
#>

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$name = "MaxSize"
$value = 32768
$currentValue = Get-ItemProperty -Path $registryPath -Name $name -ErrorAction SilentlyContinue

if (!(Test-Path $registryPath)) {
    Write-Host "Registry path not found. Creating $registryPath..." -ForegroundColor Cyan
    New-Item -Path $registryPath -Force | Out-Null
}

if ($null -eq $currentValue -or $currentValue.$name -lt $value) {
    Write-Host "Finding detected: $name is either missing or less than $value." -ForegroundColor Yellow
    
    try {
        Set-ItemProperty -Path $registryPath -Name $name -Value $value -Type DWord -ErrorAction Stop
        Write-Host "Success: $registryPath\$name has been set to $value." -ForegroundColor Green
    } catch {
        Write-Error "Failed to set registry value. Error: $_"
    }
    
} else {
    Write-Host "Compliant: $name is already set to $($currentValue.$name), which meets the requirement (>= $value)." -ForegroundColor Green
}