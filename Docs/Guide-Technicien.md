# DIAGNOSTIC RÉSEAU — GUIDE TECHNICIEN L1/L2

## 1) Objectif
Cet outil PowerShell aide au diagnostic réseau poste Windows en contexte support IT (L1/L2), GMSI et montée ASR.
Il permet d’investiguer rapidement les incidents de connectivité, DNS, DHCP, routage, ports TCP, Wi-Fi et performance.
Il ne remplace pas l’analyse humaine : il fournit des mesures et des pistes d’action.

## 2) Prérequis
- Windows 10/11.
- Windows PowerShell 5.1.
- Script local accessible.
- Droits standard suffisants pour le mode de base.
- Connectivité requise pour certains tests (DNS, Internet, charge, débit).
- Le Wi-Fi n’est pas applicable sur les postes sans interface sans fil.

## 3) Lancement rapide
Commande standard :

```powershell
powershell -ExecutionPolicy Bypass -File .\Diagnostic-Reseau.ps1
```

Exemple avancé :

```powershell
.\Diagnostic-Reseau.ps1 `
  -DnsServer "8.8.8.8" `
  -DnsTestDomains "google.com","github.com" `
  -RoutingTraceTarget "1.1.1.1" `
  -TraceMaxHops 6 `
  -TcpTarget "google.com" `
  -TcpPorts 80,443,445,3389 `
  -IncludeWifiScan `
  -LoadTestTarget "cloudflare.com" `
  -LoadTestMonitorTarget "8.8.8.8" `
  -LoadTestSampleCount 6 `
  -LoadTestDurationSec 6 `
  -LoadTestParallelStreams 2 `
  -EnableBandwidthTest `
  -OpenDashboard
```

## 4) Légende des statuts
- 🟢 OK : fonctionnement normal.
- 🟠 WARNING / AVERTISSEMENT : anomalie ou vérification nécessaire.
- 🔴 CRITICAL / ECHEC : incident important, action ou escalade nécessaire.
- ⚪ N/A : donnée indisponible ou test non applicable.

Toujours interpréter le statut avec le contexte global (poste, réseau, application, heure de l’incident).

## 5) Procédure — Pas d’Internet
1. Vérifier l’interface réseau
   - Attendu : interface UP.
   - Anomalie : interface absente/down.
   - Action : câble, carte réseau, pilote, désactivation logicielle.
2. Vérifier l’adresse IP
   - Attendu : IPv4 cohérente avec le plan d’adressage.
   - Anomalie : IP absente.
3. Vérifier APIPA (169.254.x.x)
   - Anomalie : APIPA détectée.
   - Action : vérifier DHCP/VLAN/liaison, renouveler bail.
4. Vérifier DHCP
   - Attendu : DHCP actif + serveur détecté.
   - Anomalie : serveur DHCP non détecté.
5. Tester passerelle
   - Attendu : joignable.
   - Anomalie : inaccessible.
6. Tester IP Internet
   - Attendu : ping OK.
7. Tester DNS
   - Attendu : résolution de domaines OK.
8. Vérifier routage
   - Attendu : route par défaut cohérente.
9. Tester ports TCP si nécessaire
   - Attendu : ports applicatifs ouverts selon cible/autorisations.

## 6) Procédure — Internet lent
1. Relever la latence de référence.
2. Vérifier pertes de paquets.
3. Lancer le test de charge contrôlé.
4. Comparer Avant / Charge / Après.
5. Si activé, exécuter test de débit.
6. Vérifier Wi-Fi (signal, canal, stabilité).
7. Lire l’analyse/recommandations.

Interprétation clé :
- Si la latence se dégrade sous charge avec pertes, suspecter congestion/qualité de lien.

## 7) Procédure — Application inaccessible
1. Vérifier résolution DNS du domaine applicatif.
2. Identifier l’IP cible.
3. Vérifier routage.
4. Tester port applicatif (80/443 ou port métier).
5. Lire la conclusion d’analyse.

Différencier :
- DNS : nom non résolu.
- Réseau : passerelle/Internet KO.
- Routage : chemin/route incohérente.
- Port fermé/inaccessible : filtrage/service indisponible.
- Applicatif : réseau OK mais service en défaut.

## 8) Procédure — Wi-Fi instable
1. Vérifier présence interface Wi-Fi.
2. Vérifier SSID connecté.
3. Vérifier signal et canal.
4. Vérifier latence/pertes.
5. Comparer si possible avec test Ethernet.
6. Corréler avec heures de saturation et environnement radio.

## 9) Procédure — Serveur inaccessible
1. DNS (nom du serveur).
2. IP cible (résolution/joignabilité).
3. Routage (route par défaut, traceroute).
4. TCP (port service attendu).
5. Conclusion : poste local, réseau intermédiaire, ou serveur distant.

## 10) Interprétation des rapports
- TXT : lecture rapide, ticket, archivage simple.
- JSON : automatisation, intégration, retraitement.
- HTML : lecture visuelle, partage de diagnostic.

## 11) Checklist ticket support
- Nom du poste.
- Utilisateur.
- Date/heure du test.
- Statut global.
- Symptôme utilisateur.
- IP / Masque / Passerelle.
- DHCP / APIPA.
- DNS (serveur + résolution).
- Latence / pertes.
- TCP (ports testés).
- Wi-Fi (si applicable).
- Recommandations.
- Fichiers de rapport joints.

## 12) Quand escalader (L1 → L2/L3)
L1 :
- Vérifs de base (câble/Wi-Fi/interface/IP/DHCP/DNS/passerelle).
- Exécution du diagnostic complet.

Escalade L2/L3 recommandée si :
- incident persistant malgré actions L1 ;
- anomalies de routage ;
- pertes élevées récurrentes ;
- forte dégradation sous charge ;
- serveur inaccessible alors que poste local semble sain ;
- suspicion firewall/VLAN/équipement/architecture.

Cette hiérarchie dépend de l’organisation interne.

## 13) Bonnes pratiques
- Lancer le diagnostic avant toute modification.
- Conserver les rapports.
- Noter l’heure exacte du symptôme.
- Comparer plusieurs postes en incident collectif.
- Éviter les tests de charge inutiles.
- N’utiliser que des cibles autorisées.
- Ne jamais conclure sur un seul test.

## 14) Exemple de diagnostic (fictif)
Exemple (données fictives) :
- IP : OK
- DHCP : OK
- Passerelle : OK
- Internet : OK
- DNS : WARNING
- TCP 443 : OK
- Wi-Fi : OK

Conclusion possible :
la connectivité de base est correcte ; l’anomalie est probablement DNS (serveur lent/intermittent, zone, forwarding, cache). Vérifier infra DNS avant d’incriminer l’application.

## 15) Limites de l’outil
- Dépend de la disponibilité réseau au moment du test.
- Certains retours varient selon les droits et politiques Windows.
- Wi-Fi non applicable sur toutes les machines.
- Le débit dépend de la disponibilité de la cible de test.
- L’analyse automatique aide, mais ne remplace pas l’expertise.
- Certains incidents nécessitent une analyse côté infra/serveur.

## 16) Référence rapide
- ☐ Identifier le symptôme
- ☐ Lancer le diagnostic
- ☐ Vérifier IP / APIPA
- ☐ Vérifier DHCP
- ☐ Vérifier passerelle
- ☐ Vérifier Internet
- ☐ Vérifier DNS
- ☐ Vérifier routage
- ☐ Vérifier TCP si nécessaire
- ☐ Vérifier Wi-Fi si nécessaire
- ☐ Vérifier latence/pertes
- ☐ Examiner analyse/recommandations
- ☐ Générer/conserver les rapports
- ☐ Documenter le ticket
- ☐ Escalader si nécessaire
