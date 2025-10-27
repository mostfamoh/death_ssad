# 🎯 Guide Complet des Attaques - Mode d'emploi

## ✨ Nouvelles Fonctionnalités

### 1. **Sélection du Type d'Attaque**

Vous pouvez maintenant choisir quel type d'attaque exécuter :

- **Toutes les attaques** : Brute-force + Dictionary + MitM complet
- **Brute-Force uniquement** : Teste toutes les clés possibles
- **Dictionary Attack uniquement** : Compare avec dictionnaire
- **Man-in-the-Middle complet** : Simulation complète avec analyse

### 2. **Étapes Détaillées de l'Attaque**

Cochez "Afficher les étapes détaillées" pour voir :
- 📚 Principe de l'attaque
- 🔢 Formules mathématiques
- 📊 Complexité algorithmique
- ⚠️ Vulnérabilités exposées
- 🛡️ Protections recommandées

### 3. **Support Playfair avec Clé Personnalisée**

Pour attaquer un compte Playfair :
1. Sélectionnez "Playfair" comme algorithme
2. Un champ "Clé Playfair" apparaît
3. Entrez la clé si vous la connaissez
4. Laissez vide pour essayer les clés courantes

---

## 📖 Exemples d'Utilisation

### Exemple 1 : Attaque César Complète

```
1. Créer un compte test:
   Username: testcesar
   Password: secret
   Mode: Faible
   Algorithme: César, shift=5

2. Lancer l'attaque:
   Utilisateur: testcesar
   Ciphertext: xjhwjy (récupéré après inscription)
   Algorithme: César
   Type d'attaque: Toutes les attaques
   ✅ Étapes détaillées: cochée

3. Résultats attendus:
   - Brute-Force: 26 tentatives, < 1ms
   - Mot de passe récupéré: "secret"
   - Dictionary match: "secret" trouvé
```

### Exemple 2 : Attaque Playfair avec Clé

```
1. Compte existant:
   Username: bellia
   Ciphertext: BGGNNWNW
   Algorithme: Playfair
   Clé: key

2. Lancer l'attaque:
   Utilisateur: bellia
   Ciphertext: BGGNNWNW
   Algorithme: Playfair
   Clé Playfair: key ← IMPORTANT!
   Type: Toutes les attaques

3. Résultats:
   - Déchiffrement avec clé "key"
   - Mot de passe récupéré (sans le padding X)
```

### Exemple 3 : Attaque Affine Ciblée

```
1. Créer compte Affine:
   Username: testaffine
   Password: attack
   Algorithme: Affine, a=5, b=8

2. Lancer Brute-Force uniquement:
   Utilisateur: testaffine
   Ciphertext: [obtenu après inscription]
   Algorithme: Affine
   Type d'attaque: Brute-Force uniquement
   ✅ Étapes détaillées

3. Observer:
   - 312 combinaisons testées
   - Temps: < 5ms
   - Paramètres trouvés: a=5, b=8
   - Mot de passe: "attack"
```

---

## 🎬 Démonstration Complète : Scénario Réaliste

### Scénario : Attaque d'un Compte Faible

**Phase 1 : Reconnaissance**
```
1. L'attaquant identifie un compte: "badro"
2. Via MitM, intercepte: "dfklob123"
3. Détecte l'algorithme: César (analyse pattern)
```

**Phase 2 : Attaque**
```
Interface d'attaque:
- Utilisateur cible: badro
- Ciphertext intercepté: dfklob123
- Algorithme: César
- Type d'attaque: Toutes les attaques
- ✅ Afficher étapes détaillées
```

**Phase 3 : Résultats**
```
📚 Étapes Détaillées:
  🔍 Brute-Force César
    - 26 décalages testés
    - Formule: P = (C - shift) mod 26
    - Complexité: O(26) = Triviale
  
  📖 Dictionary Attack
    - 24 mots testés
    - Aucun match (password non-standard)
  
  🕵️ Man-in-the-Middle
    - Interception réussie
    - Brute-force offline possible
    - Replay attack possible

📊 Résultats:
  ✓ Brute-Force: SUCCÈS
  🔓 Mot de passe récupéré: "dfklob123"
  ⏱️ Temps: 0.001s
  ⚠️ Compte compromis!
```

---

## 📊 Visualisation des Résultats

Les nouveaux résultats affichent :

### Cartes Métriques
```
┌───────────┐  ┌────────────┐  ┌──────────┐
│Tentatives │  │Temps écoulé│  │  Succès  │
│    26     │  │  0.001s    │  │  ✓ OUI   │
└───────────┘  └────────────┘  └──────────┘
```

### Tableau des Candidats
```
#  | Texte Déchiffré | Paramètres
---|-----------------|------------
1  | secret          | shift=5
2  | tfdsfr          | shift=6
3  | ugetsg          | shift=7
...
```

### Alertes Visuelles
- 🔓 **Rouge** : Mot de passe récupéré (danger critique)
- ⚠️ **Jaune** : Correspondances dictionnaire
- 🛡️ **Vert** : Recommandations de protection

---

## 🔐 Cas Spéciaux

### Playfair sans Clé
```
Si vous ne connaissez pas la clé Playfair:
1. Laissez le champ vide
2. Le système essaiera: key, secret, password, etc.
3. Probabilité de succès: faible sauf clé commune
```

### Hill 3×3
```
Hill est plus résistant:
- Brute-force impraticable (26^9 combinaisons)
- Nécessite known-plaintext attack
- Étapes détaillées expliquent la méthode
```

### Mode Sécurisé (pbkdf2)
```
Les comptes en mode sécurisé:
- Ne peuvent PAS être brute-forcés facilement
- Message explicite: "Mode sécurisé détecté"
- Démonstration de la bonne pratique
```

---

## 🎯 Objectifs Pédagogiques Atteints

✅ **Compréhension des vulnérabilités**
- Voir en temps réel la faiblesse des algos classiques
- Étapes détaillées expliquent le "pourquoi"

✅ **Analyse de complexité**
- César: O(26) = trivial
- Affine: O(312) = très faible
- Playfair: Dépend de la clé
- Hill: O(26^9) = impraticable (mais known-plaintext vulnérable)

✅ **Importance de la sécurité moderne**
- Comparaison directe weak vs secure
- Recommandations concrètes affichées
- Protection Diffie-Hellman démontrée

---

## 📝 Checklist de Test

Avant de rendre le TP, testez :

- [ ] Attaque César avec étapes détaillées
- [ ] Attaque Affine brute-force uniquement
- [ ] Attaque Playfair avec clé connue
- [ ] Attaque Playfair sans clé (clés courantes)
- [ ] Dictionary attack sur mot commun
- [ ] MitM complet avec analyse
- [ ] Téléchargement results.csv
- [ ] Vérification des logs horodatés
- [ ] Capture d'écran de chaque type d'attaque

---

## 🚀 Commandes Rapides

### Démarrer le serveur
```powershell
cd c:\Users\j\OneDrive\Desktop\ssad\APP
node backend\server.js
```

### Ouvrir l'application
```
http://localhost:3000
```

### Révéler les mots de passe (script utilitaire)
```powershell
node reveal_passwords.js
```

### Tester toutes les attaques automatiquement
```powershell
node test_attacks.js
```

---

## 📞 Aide Rapide

**Erreur CORS ?**
→ Ouvrez http://localhost:3000 (pas file://)

**Playfair ne déchiffre pas ?**
→ Vérifiez que la clé est exactement celle de l'inscription

**Attaque ne trouve rien ?**
→ Normal si le password n'est pas dans le dictionnaire
→ Brute-force devrait quand même trouver (César/Affine)

**Results.csv vide ?**
→ Lancez au moins une attaque d'abord
→ Vérifiez backend/data/results.csv

---

**Bon test ! 🔐🎯**
