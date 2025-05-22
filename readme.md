# 💬 Projet — Messagerie Sécurisée (ENSIBS 2024-2025)

Ce projet met en œuvre une communication **confidentielle**, **authentifiée** et **robuste** entre des clients via plusieurs mécanismes de sécurité étudiés au fil des parties.

## 🛡️ Objectifs pédagogiques

- Implémenter le chiffrement symétrique (AES) et asymétrique (RSA).
- Sécuriser un échange de clé avec Diffie-Hellman.
- Authentifier les messages avec signature numérique.
- Simuler des attaques de type MITM.
- Concevoir une messagerie sécurisée avec interface web.

---

## 🔧 Prérequis techniques

- Python 3.10+
- Modules :
  - `flask`
  - `cryptography`
  - `requests`
  - `rsa` (si utilisé)
  - `mitmproxy` (pour Partie 3)

```bash
pip install flask cryptography requests mitmproxy
````

---

## 📦 Structure du projet

```
projet/
│
├── server.py             # Serveur de confiance (génère et distribue la clé AES chiffrée RSA)
├── alice.py              # Client Alice
├── bob.py                # Client Bob
├── tristan.py            # Client Tristan
├── run_all.py            # Lance tous les services + interface
├── keys/                 # Contient les paires de clés RSA
│   ├── Alice_public.pem / private.pem
│   ├── Bob_public.pem / private.pem
│   └── Tristan_public.pem / private.pem
├── templates/
│   └── chat.html         # Interface de discussion
└── style/               # Images / favicons
```

---

## 📘 Fonctionnement par partie

### 🧩 Partie 1 — Échange sécurisé de clé AES via Diffie-Hellman

* Alice et Bob génèrent un secret partagé via **Diffie-Hellman**.
* Alice chiffre une clé AES avec ce secret (via XOR).
* Un **hash SHA-256** est utilisé pour garantir l’intégrité.
* Bob renvoie un message chiffré en AES comme confirmation.

✅ Objectifs atteints : secret partagé, intégrité, accusé de réception.

---

### 🔐 Partie 2 — Communication chiffrée RSA (Client → Serveur)

* Le serveur expose sa **clé publique** via un endpoint HTTP.
* Le client la récupère, chiffre un message et l’envoie.
* Le serveur le déchiffre avec sa clé privée et répond en clair.

✅ Objectifs atteints : chiffrement asymétrique RSA.

---

### 🕵️ Partie 3 — Attaque MITM avec mitmproxy

* Le proxy mitmproxy intercepte les échanges client-serveur.
* Modification de la requête du client / réponse du serveur.
* Vérification de l’impact en l’absence d’authentification.

✅ Objectifs atteints : analyse de vulnérabilités en transit.

---

### ✍️ Partie 4 — Intégrité & Authentification (Signature RSA)

* Le client génère une **paire RSA**.
* Il signe le message avec sa **clé privée**.
* Il envoie : message chiffré + signature + clé publique.
* Le serveur vérifie la **signature** avant d’accepter le message.

✅ Objectifs atteints : authentification, intégrité, rejet si falsification.

---

### 💬 Partie 5 — Messagerie sécurisée (multi-clients)

* Chaque client s’enregistre auprès du serveur avec sa **clé publique RSA**.
* Le serveur génère **une unique clé AES**, qu’il chiffre avec RSA pour chaque client.
* Les clients échangent ensuite les messages via **AES/Fernet**.
* Interface web développée avec **Flask + HTML/CSS**.

Fonctionnalités implémentées :

* ✅ Clés RSA stockées localement (dans `keys/`)
* ✅ Chiffrement AES/Fernet
* ✅ Signature RSA intégrée
* ✅ Timestamps (heures d’envoi)
* ✅ Interface avec avatars
* ✅ Auto-refresh toutes les 1.5 sec

---

## 🖼️ Interface

* Sélection de l'utilisateur sur `http://localhost:5005`
* Interface claire inspirée de Discord
* Avatar dynamique par utilisateur
* Timestamps discrets affichés dans les messages
* Messages différenciés (`sent` / `received`) avec bulles

---

## 🚀 Lancement

Lancez tout automatiquement avec :

```bash
python run_all.py
```

Puis ouvrez `http://localhost:5005` pour choisir un utilisateur (Alice, Bob, Tristan).

---

## ✏️ Auteurs

* Tristan Joncour, ENSIBS
* Projet dans le cadre du cours **Sécurité des communications** (2024–2025)

