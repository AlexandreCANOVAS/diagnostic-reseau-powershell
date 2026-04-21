#requires -Version 5.1

[CmdletBinding()]
param(
    [string]$DnsServer = "8.8.8.8",
    [string]$InternetHost = "google.com",
    [int]$PingCount = 2
)

$ErrorActionPreference = "SilentlyContinue"

Write-Host "=== DIAGNOSTIC RESEAU ===" -ForegroundColor Cyan

# Nom du rapport horodaté
$date = Get-Date -Format "yyyy-MM-dd_HH-mm"
$reportFile = Join-Path -Path $PSScriptRoot -ChildPath "diagnostic_$date.txt"

# Récupération de l'interface active (IPv4)
$activeConfig = Get-NetIPConfiguration |
    Where-Object { $_.IPv4Address -and $_.NetAdapter.Status -eq "Up" } |
    Select-Object -First 1

$localIp = if ($activeConfig) { $activeConfig.IPv4Address.IPAddress } else { "Non detectee" }
$gateway = if ($activeConfig -and $activeConfig.IPv4DefaultGateway) { $activeConfig.IPv4DefaultGateway.NextHop } else { "Non detectee" }

# Fonction utilitaire de test ping
function Test-NetworkTarget {
    param(
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ([string]::IsNullOrWhiteSpace($Target) -or $Target -eq "Non detectee") {
        return [PSCustomObject]@{
            Test   = $Label
            Cible  = $Target
            Statut = "ECHEC"
            Detail = "Cible indisponible"
        }
    }

    $result = Test-Connection -ComputerName $Target -Count $PingCount -Quiet

    [PSCustomObject]@{
        Test   = $Label
        Cible  = $Target
        Statut = if ($result) { "OK" } else { "ECHEC" }
        Detail = if ($result) { "Connexion reussie" } else { "Aucune reponse" }
    }
}

Write-Host "`n[1] Adresse IP locale :" -ForegroundColor Yellow
Write-Host "IP : $localIp"
Write-Host "Passerelle : $gateway"

Write-Host "`n[2] Test connexion Internet ($InternetHost) :" -ForegroundColor Yellow
$internetTest = Test-NetworkTarget -Target $InternetHost -Label "Connexion Internet"
Write-Host "$($internetTest.Statut) - $($internetTest.Detail)"

Write-Host "`n[3] Test passerelle ($gateway) :" -ForegroundColor Yellow
$gatewayTest = Test-NetworkTarget -Target $gateway -Label "Passerelle"
Write-Host "$($gatewayTest.Statut) - $($gatewayTest.Detail)"

Write-Host "`n[4] Test DNS ($DnsServer) :" -ForegroundColor Yellow
$dnsTest = Test-NetworkTarget -Target $DnsServer -Label "DNS"
Write-Host "$($dnsTest.Statut) - $($dnsTest.Detail)"

# Construction du rapport
$reportLines = @(
    "=== DIAGNOSTIC RESEAU ===",
    "Date : $(Get-Date -Format \"dd/MM/yyyy HH:mm:ss\")",
    "Machine : $env:COMPUTERNAME",
    "Utilisateur : $env:USERNAME",
    "",
    "[1] Configuration locale",
    "IP locale : $localIp",
    "Passerelle : $gateway",
    "",
    "[2] Resultats des tests",
    "- $($internetTest.Test) [$($internetTest.Cible)] : $($internetTest.Statut) - $($internetTest.Detail)",
    "- $($gatewayTest.Test) [$($gatewayTest.Cible)] : $($gatewayTest.Statut) - $($gatewayTest.Detail)",
    "- $($dnsTest.Test) [$($dnsTest.Cible)] : $($dnsTest.Statut) - $($dnsTest.Detail)",
    "",
    "[3] ipconfig /all",
    ""
)

$reportLines | Out-File -FilePath $reportFile -Encoding UTF8
ipconfig /all | Out-File -FilePath $reportFile -Append -Encoding UTF8

Write-Host "`n[5] Sauvegarde du rapport..." -ForegroundColor Yellow
Write-Host "Diagnostic termine. Rapport sauvegarde : $reportFile" -ForegroundColor Green
