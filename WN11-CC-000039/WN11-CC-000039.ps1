<#
.SYNOPSIS
    Run as different user must be removed from context menus.

.NOTES
    Author          : Imran (Ian) Huhn
    LinkedIn        : linkedin.com/in/ianhuhntech
    GitHub          : github.com/IanImranHuhn
    Date Created    : 2026-01-07
    Last Modified   : 2026-01-08
    Version         : 1.1
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000039
    STIGaview Link  : https://stigaview.com/products/win11/v2r5/WN11-CC-000039/

.TESTED ON
    Date(s) Tested  : 2026-01-07, 2026-01-08
    Tested By       : Imran (Ian) Huhn
    Systems Tested  : Windows 11 Pro (22H2)
    PowerShell Ver. : 5.1.26100.7462 

.USAGE
    Run this script in an elevated PowerShell session:
        PS C:\> .\WN11-CC-000039.ps1 
#>

$RegistryPaths = @(
    "HKLM:\SOFTWARE\Classes\batfile\shell\runasuser",
    "HKLM:\SOFTWARE\Classes\cmdfile\shell\runasuser",
    "HKLM:\SOFTWARE\Classes\exefile\shell\runasuser",
    "HKLM:\SOFTWARE\Classes\mscfile\shell\runasuser"
)
$ValueName    = "SuppressionPolicy"
$DesiredValue = 4096

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as an Administrator."
    exit
}

foreach ($Path in $RegistryPaths) {
    $CurrentValue = Get-ItemProperty -Path $Path -Name $ValueName -ErrorAction SilentlyContinue
    
    Write-Host "Processing Path: $Path" -ForegroundColor Gray

    if (-not (Test-Path $Path)) {
        try {
            Write-Host "  Creating missing registry path..." -ForegroundColor Cyan
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        } catch {
            Write-Warning "  Failed to create path $Path. Access might be restricted by permissions."
            continue
        }
    }

    if ($null -eq $CurrentValue -or $CurrentValue.$ValueName -ne $DesiredValue) {
        Write-Host "  Setting $ValueName to $DesiredValue..." -ForegroundColor Yellow
        Set-ItemProperty -Path $Path -Name $ValueName -Value $DesiredValue -Type DWord -Force
    } else {
        Write-Host "  Value is already correctly configured." -ForegroundColor Green
    }
}

Write-Host "`nRemediation complete." -ForegroundColor White