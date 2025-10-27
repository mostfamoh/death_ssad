# 🔐 TP Cryptographie Classique - Boîte à Outils Éducative

[![Node.js](https://img.shields.io/badge/Node.js-v18+-green.svg)](https://nodejs.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Educational-yellow.svg)](.)

## 📋 Description

Ce projet développe une boîte à outils éducative pour expérimenter des algorithmes de chiffrement classiques (**César, Affine, Playfair, Hill 3×3**) et des attaques ciblant l'étape d'authentification (brute-force, dictionnaire, Man-in-the-Middle). 

**L'objectif est pédagogique** : démontrer les faiblesses des méthodes simples lorsqu'elles sont utilisées pour l'authentification, et présenter une solution d'amélioration basée sur **Diffie–Hellman + HMAC/pbkdf2**.

### 🎯 Objectifs du TP

- ✅ Implémenter 4 algorithmes de chiffrement classiques (chiffrement/déchiffrement)
- ✅ Créer un système d'authentification avec deux modes (faible/sécurisé)
- ✅ Simuler et mesurer des attaques (Brute-force, Dictionary, MitM)
- ✅ Démontrer la protection par Diffie-Hellman + stockage sécurisé (pbkdf2)
- ✅ Logger et analyser les résultats dans `results.csv`

---

## 🏗️ Architecture du Projet

```
APP/
├── backend/
│   ├── server.js                  # Serveur HTTP Node.js (sans framework)
│   ├── utils/
│   │   ├── ciphers.js            # César, Affine, Playfair, Hill 3×3
│   │   ├── attacks.js            # Brute-force, Dictionary, MitM
│   │   └── secure.js             # Diffie-Hellman, pbkdf2, HMAC
│   └── data/
│       ├── users.json            # Base de données utilisateurs
│       ├── dict_small.txt        # Dictionnaire pour attaques
│       └── results.csv           # Logs des attaques
│
├── frontend/
│   ├── index.html                # Interface Bootstrap
│   ├── app.js                    # Logique frontend (Vanilla JS)
│   └── style.css                 # Styles personnalisés
│
├── README.md                     # Ce fichier
└── report.md                     # Rapport technique complet
```

---

## 🚀 Installation et Exécution

### Prérequis

- **Node.js** v18+ ([Télécharger ici](https://nodejs.org/))
- Un navigateur web moderne (Chrome, Firefox, Edge)

### Étapes d'installation

1. **Cloner ou télécharger le projet**
   ```powershell
   cd c:\Users\j\OneDrive\Desktop\ssad\APP
   ```

2. **Aucune installation de dépendances nécessaire** (modules Node.js standard uniquement)

3. **Démarrer le serveur backend**
   ```powershell
   node backend\server.js
   ```

   Le serveur démarre sur **http://localhost:3000**

4. **Ouvrir l'interface web**
   - Ouvrir votre navigateur
   - Aller à **http://localhost:3000**
   - L'application se charge automatiquement

### Vérification

Si tout fonctionne correctement, vous devriez voir :
```
╔════════════════════════════════════════════════════════════╗
║  TP Cryptographie Classique - Serveur démarré             ║
╠════════════════════════════════════════════════════════════╣
║  🌐 URL: http://localhost:3000                             ║
║  📁 Frontend: C:\Users\j\...\APP\frontend                  ║
║  💾 Data: C:\Users\j\...\APP\backend\data                  ║
╚════════════════════════════════════════════════════════════╝
```

---

## 📚 Guide d'Utilisation

### 1. Inscription (Register)

**Mode Faible (Pédagogique)** ⚠️
- Choisir "Faible (chiffrement classique)"
- Sélectionner un algorithme (César, Affine, Playfair, Hill)
- Configurer les paramètres (shift, clé, matrice)
- Le mot de passe est stocké **chiffré** par l'algorithme choisi
- **Vulnérabilité** : facilement cassable par brute-force

**Mode Sécurisé** ✅
- Choisir "Sécurisé (pbkdf2 + salt)"
- Le mot de passe est hashé avec **200,000 itérations pbkdf2**
- Un **salt aléatoire** unique est généré
- **Sécurité** : résistant aux attaques par force brute

### 2. Connexion (Login)

**Connexion Standard**
- Entrer nom d'utilisateur et mot de passe
- Le serveur vérifie selon le mode d'inscription

**Avec Diffie-Hellman** 🔐
- Cocher "Utiliser Diffie-Hellman"
- Un échange de clés sécurisé est effectué :
  1. Client génère `a`, calcule `A = g^a mod p`
  2. Serveur génère `b`, calcule `B = g^b mod p`
  3. Clé partagée : `K = g^(ab) mod p`
- L'authentification utilise cette clé de session

### 3. Outils de Chiffrement

4 onglets disponibles :

**César**
- Décalage alphabétique simple
- Paramètre : shift (1-25)
- Exemple : `HELLO` + shift 3 → `KHOOR`

**Affine**
- Transformation : `C = (aP + b) mod 26`
- Paramètres : `a` (premier avec 26), `b` (0-25)
- Exemple : `HELLO` + a=5, b=8 → `RCLLA`

**Playfair**
- Chiffrement par digrammes (paires de lettres)
- Matrice 5×5 basée sur une clé
- I et J fusionnés

**Hill 3×3**
- Chiffrement matriciel par blocs de 3 lettres
- Nécessite une matrice 3×3 inversible mod 26
- Padding automatique avec 'X'

### 4. Simulation d'Attaques

**Configuration de l'attaque** 🎯
- Entrer le nom d'utilisateur cible
- Fournir le ciphertext intercepté
- Sélectionner l'algorithme utilisé
- Cliquer "Lancer l'attaque MitM"

**Types d'attaques simulées** :

1. **Brute-Force César** (26 tentatives)
   - Teste toutes les clés possibles
   - Temps : < 1ms
   - **Conclusion** : Totalement cassable

2. **Brute-Force Affine** (312 tentatives)
   - 12 valeurs de `a` × 26 valeurs de `b`
   - Temps : < 5ms
   - **Conclusion** : Très rapide à casser

3. **Dictionary Attack**
   - Compare avec `dict_small.txt`
   - Efficace si le mot de passe est commun
   - **Conclusion** : Dangereux pour mots de passe faibles

4. **Man-in-the-Middle (MitM)**
   - Interception du trafic d'authentification
   - Replay attack possible
   - MitM sur DH sans authentification

**Télécharger les résultats**
- Cliquer "Télécharger results.csv"
- Format : `timestamp, username, attack_type, target, attempts, elapsed_seconds, success, recovered_plaintext`

---

## 🔬 Algorithmes Implémentés

### César
- **Principe** : Décalage circulaire dans l'alphabet
- **Espace de clés** : 26 (trivial)
- **Sécurité** : ⚠️ Aucune (brute-force instantané)

### Affine
- **Principe** : `C = (aP + b) mod 26`
- **Espace de clés** : 312 combinaisons
- **Sécurité** : ⚠️ Très faible
- **Condition** : `gcd(a, 26) = 1`

### Playfair
- **Principe** : Chiffrement par digrammes (5×5)
- **Espace de clés** : ~10^26 (théorique)
- **Sécurité** : ⚠️ Vulnérable à l'analyse de fréquence
- **Particularité** : I/J fusionnés, padding 'X'

### Hill 3×3
- **Principe** : Multiplication matricielle mod 26
- **Espace de clés** : ~10^38 (théorique)
- **Sécurité** : ⚠️ Vulnérable à known-plaintext attack
- **Condition** : Matrice inversible (det premier avec 26)

---

## 🛡️ Mécanismes de Sécurité

### Diffie-Hellman (Échange de Clés)

```
Client                          Serveur
  |                                |
  | Génère a, calcule A=g^a mod p  |
  |------------ A ---------------→ |
  |                                | Génère b, calcule B=g^b mod p
  |←----------- B -----------------|
  |                                |
  | K = B^a mod p                  | K = A^b mod p
  | (clé partagée)                 | (clé partagée)
```

**Paramètres utilisés** :
- Prime `p` : 2048 bits (groupe modp14 simplifié)
- Générateur `g` : 2

**⚠️ Vulnérabilité** : Sans authentification (signatures), un attaquant peut effectuer un double échange DH (MitM).

### pbkdf2 (Stockage Sécurisé)

```javascript
hash = pbkdf2(password, salt, 200000 iterations, sha512)
```

**Avantages** :
- ✅ Résistant au brute-force (itérations coûteuses)
- ✅ Salt unique par utilisateur (empêche rainbow tables)
- ✅ Dérivation standard (compatible, auditée)

**Alternative recommandée** : Argon2 (meilleur contre GPU/ASIC)

### HMAC (Authentification de Messages)

```javascript
hmac = HMAC-SHA256(sessionKey, password || nonce)
```

**Usage** : Authentifier sans envoyer le mot de passe en clair après échange DH.

---

## 📊 Résultats et Logs

### Format CSV (`results.csv`)

```csv
timestamp,username,attack_type,target,attempts,elapsed_seconds,success,recovered_plaintext
2025-10-26T...,alice,Caesar Brute-Force,KHOOR,26,0.003,true,HELLO
2025-10-26T...,bob,Affine Brute-Force,RCLLA,312,0.015,true,HELLO
2025-10-26T...,charlie,Dictionary Attack,JRYPBZR,500,0.021,true,WELCOME
```

### Analyse des Performances

| Attaque | Tentatives | Temps Moyen | Taux de Succès |
|---------|-----------|-------------|----------------|
| César BF | 26 | < 1ms | 100% |
| Affine BF | 312 | < 5ms | 100% |
| Dictionary | 500-10k | < 50ms | 30-60% |
| Hill BF | Impraticable | N/A | 0% (espace trop grand) |

**Conclusion** : Les algorithmes classiques sont **totalement inadaptés** pour l'authentification moderne.

---

## ⚠️ Limitations et Avertissements

### 🚨 AVERTISSEMENT DE SÉCURITÉ

**CE PROJET EST STRICTEMENT ÉDUCATIF. NE JAMAIS UTILISER EN PRODUCTION.**

**Pourquoi ?**
- ❌ Pas de TLS/HTTPS (communication en clair)
- ❌ Pas de rate-limiting (brute-force en ligne possible)
- ❌ Pas de système de sessions robuste
- ❌ Pas de validation d'entrée rigoureuse
- ❌ Diffie-Hellman non authentifié (vulnérable MitM)
- ❌ Stockage en JSON (pas de base de données sécurisée)

### Recommandations pour Production

1. **Authentification** : OAuth 2.0 / OpenID Connect
2. **Stockage** : Argon2 ou bcrypt avec coût adaptatif
3. **Transport** : TLS 1.3 uniquement
4. **Échange de clés** : TLS 1.3 (ephemeral ECDH + signatures)
5. **Rate-limiting** : Limiter tentatives de login (fail2ban, etc.)
6. **MFA** : TOTP, WebAuthn (FIDO2)

---

## 🧪 Tests et Validation

### Scénarios de Test

**Test 1 : Inscription Mode Faible**
```
1. Créer compte avec César (shift=3)
2. Mot de passe : "hello"
3. Vérifier stockage : "khoor"
4. Lancer attaque → Récupération : "hello" ✓
```

**Test 2 : Inscription Mode Sécurisé**
```
1. Créer compte avec pbkdf2
2. Mot de passe : "SecurePass123!"
3. Vérifier hash + salt stockés
4. Lancer brute-force → Échec (espace trop grand) ✓
```

**Test 3 : Échange Diffie-Hellman**
```
1. Se connecter avec DH activé
2. Observer échange A ↔ B
3. Vérifier clé partagée identique client/serveur ✓
```

### Validation des Algorithmes

Tous les algorithmes ont été validés avec des vecteurs de test standards :
- ✅ César : ROT13 ("HELLO" → "URYYB")
- ✅ Affine : Inverse correctement calculé
- ✅ Playfair : Conforme aux règles standard
- ✅ Hill : Matrice inversible vérifiée (det=1 mod 26)

---

## 📖 Documentation Complémentaire

### Fichiers du Projet

- **`server.js`** : Serveur HTTP + routage + handlers
- **`ciphers.js`** : Implémentations complètes des 4 algorithmes
- **`attacks.js`** : Brute-force, dictionary, MitM simulations
- **`secure.js`** : DH, pbkdf2, HMAC, AES-GCM
- **`app.js`** : Frontend (fetch API, DH client, UI)
- **`report.md`** : Rapport technique détaillé (théorie, analyse, résultats)

### Lectures Recommandées

- [Applied Cryptography - Bruce Schneier](https://www.schneier.com/books/applied-cryptography/)
- [RFC 2631 - Diffie-Hellman Key Agreement](https://datatracker.ietf.org/doc/html/rfc2631)
- [NIST SP 800-132 - Password-Based Key Derivation](https://csrc.nist.gov/publications/detail/sp/800-132/final)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

---

## 🤝 Contribution et Support

Ce projet est développé dans un cadre éducatif. Pour toute question :

1. Consulter le **rapport technique** (`report.md`)
2. Vérifier la **console du navigateur** (F12)
3. Consulter les **logs du serveur** (terminal)

### Structure du Code

- **Commentaires détaillés** dans tous les fichiers
- **Fonctions modulaires** réutilisables
- **Validation des entrées** côté serveur
- **Gestion d'erreurs** robuste

---

## 📜 Licence

MIT License - Projet éducatif © 2025

**Disclaimer** : Ce projet démontre des vulnérabilités de sécurité à des fins pédagogiques. L'utilisation de ces techniques contre des systèmes réels sans autorisation est illégale.

---

## 🎓 Crédits

**Technologies utilisées** :
- Node.js (modules `http`, `fs`, `crypto`)
- Bootstrap 5.3
- Bootstrap Icons
- JavaScript Vanilla (ES6+)

**Concepts cryptographiques** :
- Chiffrements classiques (historiques)
- Diffie-Hellman (Whitfield Diffie, Martin Hellman, 1976)
- PBKDF2 (PKCS #5, RFC 2898)
- HMAC (RFC 2104)

---

## 📞 Contact

Pour toute question pédagogique, consulter :
- **Rapport technique** : `report.md`
- **Code source** : Commentaires inline
- **Résultats** : `backend/data/results.csv`

---

**Bon apprentissage! 🚀🔐**
