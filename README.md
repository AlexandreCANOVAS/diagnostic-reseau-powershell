# Outil de diagnostic réseau automatique (PowerShell)

Mini projet orienté **support IT niveau 1**.

## Objectif

Diagnostiquer rapidement un problème réseau sur un poste Windows en automatisant les vérifications essentielles.

## Fonctionnalités

Le script `Diagnostic-Reseau.ps1` :

- détecte l'adresse IP locale ;
- détecte la passerelle par défaut ;
- teste la connexion Internet (hôte : `google.com`) ;
- teste la passerelle ;
- teste un DNS public (par défaut : `8.8.8.8`) ;
- affiche un résultat clair (`OK` / `ECHEC`) ;
- génère un rapport horodaté `.txt`.

## Prérequis

- Windows 10/11
- PowerShell 5.1+

## Exécution

Depuis le dossier du projet :

```powershell
powershell -ExecutionPolicy Bypass -File .\Diagnostic-Reseau.ps1
```

## Paramètres optionnels

```powershell
powershell -ExecutionPolicy Bypass -File .\Diagnostic-Reseau.ps1 -DnsServer 1.1.1.1 -InternetHost cloudflare.com -PingCount 3
```

- `-DnsServer` : serveur DNS à tester
- `-InternetHost` : hôte utilisé pour valider l'accès Internet
- `-PingCount` : nombre de requêtes ping par test

## Sortie

Le rapport est créé dans le même dossier, avec un nom du type :

- `diagnostic_2026-04-22_01-15.txt`
