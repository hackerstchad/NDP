# 🔷 NDP MASTER — Protocole Neighbor Discovery Protocol

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Orbitron&size=30&duration=3000&pause=1000&color=00F0FF&center=true&vCenter=true&width=800&lines=NDP+MASTER;Neighbor+Discovery+Protocol;IPv6+Security;by+hackers_tchad+%F0%9F%87%B9%F0%9F%87%AC" alt="NDP MASTER" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/NDP%20MASTER-v1.0.0-00F0FF?style=for-the-badge">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python">
  <img src="https://img.shields.io/badge/Lignes-1000%2B-success?style=for-the-badge">
  <img src="https://img.shields.io/badge/Éducatif-Réseau-cyan?style=for-the-badge">
</p>

---

## 🌍 Présentation

**NDP MASTER** est un outil éducatif avancé créé par **hackers_tchad 🇹🇩** pour comprendre, pratiquer et visualiser le protocole **NDP (Neighbor Discovery Protocol)** utilisé en IPv6.

> 🎯 **Mission** : apprendre le fonctionnement réel de NDP (RFC 4861), ses messages, ses menaces et ses contre-mesures de sécurité.

---

## ⚠️ Avertissement

```diff
- Outil strictement éducatif.
- Utilisez uniquement sur des réseaux que vous êtes autorisé à tester.
- Le sniffing/injection nécessite souvent les privilèges root/admin.
```

---

## 📚 Qu'est-ce que NDP ?

**NDP (Neighbor Discovery Protocol)** est un protocole de la couche réseau IPv6 défini dans la **RFC 4861**. Il combine et remplace plusieurs protocoles IPv4 :

| IPv4 | IPv6 équivalent |
|------|-----------------|
| ARP | NDP Neighbor Solicitation / Advertisement |
| ICMP Router Discovery | NDP Router Solicitation / Advertisement |
| ICMP Redirect | NDP Redirect |

### 🎯 Fonctions principales de NDP

1. **Découverte des routeurs** : trouver les routeurs sur le lien local.
2. **Autoconfiguration sans état (SLAAC)** : obtenir un préfixe réseau et configurer une IPv6.
3. **Résolution d'adresses** : associer une IPv6 à une adresse MAC.
4. **Détection de reachability** : savoir si un voisin est joignable.
5. **Détection d'adresses dupliquées (DAD)** : vérifier qu'une adresse est unique.
6. **Redirection** : orienter le trafic vers une meilleure passerelle.

---

## 📦 Types de messages NDP (ICMPv6)

| Type ICMPv6 | Nom | Rôle |
|-------------|-----|------|
| 133 | Router Solicitation (RS) | Demande aux routeurs de s'annoncer. |
| 134 | Router Advertisement (RA) | Annonce des routeurs (préfixe, MTU, DNS, etc.). |
| 135 | Neighbor Solicitation (NS) | Demande la MAC associée à une IPv6. |
| 136 | Neighbor Advertisement (NA) | Réponse avec la MAC demandée. |
| 137 | Redirect | Redirige le trafic vers une meilleure route. |

---

## 🛠️ Installation

```bash
# Cloner ou copier les fichiers
cd /workspace

# Créer un environnement virtuel (optionnel)
python3 -m venv venv
source venv/bin/activate

# Installer les dépendances
pip install -r requirements_ndp.txt
```

---

## 🚀 Commandes

### Lancer l'interface graphique

```bash
python3 ndp_master.py
```

### Mode automatique

```bash
python3 ndp_master.py --auto
```

### Commandes disponibles dans le terminal intégré

| Commande | Description |
|----------|-------------|
| `help` | Afficher l'aide |
| `scan` | Scanner le réseau local NDP (simulation) |
| `send rs` | Envoyer un Router Solicitation simulé |
| `send ra` | Envoyer un Router Advertisement simulé |
| `send ns` | Envoyer un Neighbor Solicitation simulé |
| `send na` | Envoyer un Neighbor Advertisement simulé |
| `send redirect` | Envoyer un Redirect simulé |
| `show neighbors` | Afficher la table de voisins |
| `show routers` | Afficher les routeurs découverts |
| `clear` | Vider le terminal |
| `export json` | Exporter les résultats en JSON |
| `export csv` | Exporter les résultats en CSV |
| `quiz` | Ouvrir le quiz NDP |
| `exit` / `quit` | Quitter l'application |

### Commandes système utiles pour NDP

#### Linux

```bash
# Afficher la table de voisins IPv6
ip -6 neighbor show

# Vider la table de voisins
ip -6 neighbor flush all

# Envoyer une solicitation de voisin
ndisc6 <target-ipv6> <interface>

# Découvrir les routeurs
rdisc6 <interface>

# Afficher les interfaces IPv6
ip -6 addr show
```

#### Cisco IOS

```ios
# Afficher les voisins IPv6
show ipv6 neighbors

# Afficher les interfaces IPv6
show ipv6 interface brief

# Activer RA Guard
ipv6 nd raguard

# Activer ND Inspection
ipv6 nd inspection
```

#### Windows

```powershell
# Afficher les voisins IPv6
netsh interface ipv6 show neighbors

# Supprimer les voisins
netsh interface ipv6 delete neighbors
```

---

## ✨ Fonctionnalités

- 🖥️ Interface graphique Tkinter futuriste bleue/cyan
- 📘 Cours complet intégré sur NDP (RFC 4861)
- 📦 Simulation des 5 messages NDP
- 🌐 Table de voisins dynamique
- 💻 Terminal intégré avec commandes CLI
- 🕸️ Visualisation réseau 2D animée
- 🛡️ Section sécurité NDP (menaces & contre-mesures)
- ❓ Quiz interactif
- 📤 Export JSON / CSV
- 🔍 Sniffing NDP réel avec Scapy (mode root)
- 🎨 Animation d'en-tête

---

## 🛡️ Sécurité NDP

### Menaces

- **Router Advertisement Spoofing** : fausses annonces de routeur.
- **Neighbor Advertisement Spoofing** : usurpation de voisin (équivalent ARP spoofing).
- **Redirect Attacks** : détournement de trafic.
- **DAD Denial of Service** : blocage de la détection d'adresses dupliquées.

### Contre-mesures

- **RA Guard** (RFC 6105)
- **ND Inspection / ND Snooping**
- **SEND (Secure Neighbor Discovery, RFC 3971)**
- **DHCPv6 Guard**
- **IPv6 Source Guard**

---

## 📚 Ressources d'apprentissage

### RFCs officielles

- [RFC 4861 — Neighbor Discovery for IP version 6 (IPv6)](https://datatracker.ietf.org/doc/html/rfc4861)
- [RFC 4862 — IPv6 Stateless Address Autoconfiguration](https://datatracker.ietf.org/doc/html/rfc4862)
- [RFC 3971 — SEcure Neighbor Discovery (SEND)](https://datatracker.ietf.org/doc/html/rfc3971)
- [RFC 6105 — IPv6 Router Advertisement Guard](https://datatracker.ietf.org/doc/html/rfc6105)

### Articles et tutoriels

- [Cisco — IPv6 Neighbor Discovery](https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/ipv6/113577-ndp-problem.html)
- [Wireshark Wiki — IPv6](https://wiki.wireshark.org/IPv6)
- [Scapy IPv6 Documentation](https://scapy.readthedocs.io/en/latest/layers/inet6.html)

### Vidéos recommandées

- Rechercher sur YouTube : "IPv6 NDP explained" ou "Neighbor Discovery Protocol tutorial"

---

## 🧪 Exemple de session

```bash
$ python3 ndp_master.py --auto
[14:32:10] NDP MASTER v1.0.0 Terminal [Prêt]
[14:32:10] Mode automatique activé.
>>> scan
[14:32:15] Lancement du scan NDP simulé...
[14:32:18] Voisin découvert : fe80::1234:5678:9abc:def0 -> aa:bb:cc:dd:ee:ff
>>> send ns
[14:32:25] Envoi simulé : NS de fe80::... vers ff02::1
>>> show neighbors
[14:32:30] Table de voisins : 1 entrée(s)
>>> quiz
[14:32:35] Ouverture du quiz NDP
```

---

## 📂 Fichiers

```
ndp_master.py          # Application principale (1000+ lignes)
requirements_ndp.txt   # Dépendances
README_NDP.md          # Documentation
```

---

## 📝 Licence

MIT © hackers_tchad — 2024
