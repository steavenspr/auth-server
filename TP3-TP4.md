Voici la transcription intégrale et détaillée de votre document technique pour les TP3 et TP4, structurée au format Markdown avec toutes les citations correspondantes.

---

# TP3 — Authentification Forte
[cite_start]**Serveur d'Authentification — D. Samfat** [cite: 1, 2]

## 1. Objectif du TP3
* [cite_start]L'objectif change fondamentalement par rapport aux TPs précédents[cite: 3, 4].
* [cite_start]Il ne s'agit plus seulement d'améliorer le stockage du mot de passe, mais de changer entièrement le protocole d'authentification[cite: 5].
* [cite_start]Le mot de passe ne doit plus être transmis tel quel dans la requête de login, même sous forme hachée[cite: 6].
* [cite_start]Le client doit prouver qu'il connaît un secret, sans jamais l'envoyer directement au serveur[cite: 7].
* [cite_start]La durée estimée du travail est de dix heures (une semaine de travail)[cite: 8].
* [cite_start]Le tag Git final attendu est **v3-tp3**[cite: 9].

## 2. Nouvelles fonctionnalités introduites
[cite_start]Le TP3 introduit plusieurs mécanismes cryptographiques inédits[cite: 10, 11]:
* [cite_start]**Clé secrète partagée** : Sert de base à tout le protocole[cite: 12].
* [cite_start]**HMAC (Hash-based Message Authentication Code)** : Permet de prouver la connaissance d'un secret[cite: 13].
* [cite_start]**Nonce** : Identifiant unique à usage unique généré à chaque connexion[cite: 14].
* [cite_start]**Timestamp** : Date et heure actuelles en secondes depuis l'epoch Unix[cite: 15].
* [cite_start]**Comparaison en temps constant** : Empêche les attaques par mesure du temps de réponse[cite: 16].
* [cite_start]**Protection anti-rejeu** : Empêche qu'une requête interceptée soit renvoyée plus tard[cite: 17].
* [cite_start]**SonarCloud** : Doit être conservé avec un objectif de couverture de tests minimum de 80%[cite: 18].

### 2.1 Concepts et Principes
* [cite_start]**Concept pédagogique** : Passage d'un modèle d'envoi de mot de passe à un modèle de preuve de connaissance sans envoi[cite: 19, 20]. [cite_start]Cela garantit que l'attaquant ne peut pas récupérer le mot de passe en interceptant la communication[cite: 21].
* [cite_start]**Principe global** : Chaque utilisateur possède un secret partagé dérivé de son mot de passe[cite: 22, 23]. [cite_start]Ce secret est stocké sur le serveur sous forme chiffrée ou dérivée[cite: 24]. [cite_start]L'authentification est de type Single Sign On (SSO) en un seul échange réseau[cite: 25].
* [cite_start]**Hypothèses de travail** : TLS est supposé fonctionnel[cite: 27, 28]. [cite_start]Le serveur stocke le mot de passe de manière réversible en base de données[cite: 30]. [cite_start]Une **Server Master Key (SMK)** est utilisée pour le chiffrement/déchiffrement[cite: 31].

---

## 3. Le protocole d'authentification SSO

### 3.1 Étape 1 — Côté client
1. [cite_start]Le client récupère l'email et le mot de passe saisis[cite: 33, 34, 35].
2. [cite_start]Il génère un **nonce** (UUID aléatoire unique)[cite: 36].
3. [cite_start]Il récupère le **timestamp** actuel (secondes epoch Unix)[cite: 37].
4. [cite_start]Construction du message : `message = email + ":" + nonce + ":" + timestamp`[cite: 38, 39].
5. [cite_start]Calcul du HMAC-SHA256 : `hmac = HMAC_SHA256(key = password, data = message)`[cite: 40, 41].
6. [cite_start]Envoi d'un **POST** vers `/api/auth/login` (email, nonce, timestamp, hmac)[cite: 42]. [cite_start]Le mot de passe n'est jamais inclus[cite: 43].

### 3.2 Étape 2 — Côté serveur (Ordre strict des vérifications)
1. [cite_start]Vérifier l'existence de l'email (sinon HTTP 401)[cite: 45, 46].
2. [cite_start]Vérifier le timestamp dans la fenêtre de **±60 secondes** (sinon HTTP 401)[cite: 47, 48].
3. [cite_start]Vérifier que le nonce n'a pas déjà été utilisé pour cet utilisateur (sinon HTTP 401)[cite: 49, 50].
4. [cite_start]**Réserver le nonce immédiatement** en base avec `consumed = false` pour contrer les attaques simultanées[cite: 51, 52].
5. [cite_start]Récupérer le mot de passe en clair via la **SMK**[cite: 53].
6. [cite_start]Recalculer le HMAC attendu et le comparer en **temps constant** avec `MessageDigest.isEqual()`[cite: 54, 55].
7. [cite_start]Si différents, retourner HTTP 401[cite: 56].
8. [cite_start]Marquer le nonce comme consommé (`consumed = true`)[cite: 57].
9. [cite_start]Émettre le token SSO (accessToken et expiresAt)[cite: 58].

---

## 4. Considérations techniques

### [cite_start]4.1 Structure des tables [cite: 60, 61]
* [cite_start]**`users`** : `id`, `email`, `password_encrypted`, `created_at`[cite: 62]. [cite_start]Le mot de passe est chiffré (réversible) pour permettre le recalcul du HMAC[cite: 63].
* [cite_start]**`auth_nonce`** : `id`, `user_id`, `nonce`, `expires_at`, `consumed`, `created_at`[cite: 64]. [cite_start]Unicité sur le couple `(user_id, nonce)`[cite: 65]. [cite_start]`expires_at` fixé à environ T + 2 minutes[cite: 66].

### [cite_start]4.2 Paramètres recommandés [cite: 67, 68]
| Paramètre | Valeur recommandée |
| :--- | :--- |
| Fenêtre timestamp acceptée | 60 secondes (±60s) |
| TTL du nonce en base | 120 secondes |
| Durée validité Access Token | 15 minutes |

---

## 5. Exigences Qualité et Tags

### [cite_start]5.1 Tests JUnit obligatoires (15 minimum) [cite: 70, 71]
* [cite_start]Login OK (HMAC valide)[cite: 72].
* [cite_start]Login KO (HMAC invalide)[cite: 73].
* [cite_start]KO (Timestamp expiré ou futur)[cite: 74, 75].
* [cite_start]KO (Nonce déjà utilisé / anti-rejeu)[cite: 76].
* [cite_start]KO (Utilisateur inconnu)[cite: 77].
* [cite_start]Test de comparaison en temps constant (`verifyConstantTime`)[cite: 78].
* [cite_start]Token émis et accès à `/api/me` (avec et sans token)[cite: 79, 80].

### 5.2 SonarCloud et JavaDoc
* [cite_start]Couverture minimum de **80%** et Quality Gate vert[cite: 81, 82, 83].
* [cite_start]La JavaDoc doit préciser que le mécanisme est pédagogique et qu'en production, on utiliserait un hash non réversible[cite: 84, 85, 86].

### [cite_start]5.3 Tags Git imposés [cite: 87, 88, 89, 90]
| Tag | Description |
| :--- | :--- |
| **v3.0-start** | Initialisation du TP3 |
| **v3.1-db-nonce** | Création de la table auth_nonce |
| **v3.2-hmac-client** | Calcul HMAC côté client JavaFX |
| **v3.3-hmac-server** | Vérification HMAC côté serveur |
| **v3.4-anti-replay** | Protection anti-rejeu (nonce) |
| **v3.5-token** | Émission token SSO et /api/me |
| **v3.6-tests-80** | Tests JUnit complets et SonarCloud ≥ 80% |
| **v3-tp3** | Tag final du TP3 |

---

# TP4 — Authentification et Master Key
[cite_start]**Serveur d'Authentification — D. Samfat** [cite: 100, 101]

## 1. Objectif du TP4
* [cite_start]Le protocole HMAC du TP3 reste inchangé[cite: 102, 103].
* [cite_start]L'objectif est l'industrialisation : protection par **Master Key**, automatisation par **GitHub Actions**, et blocage des merges[cite: 104, 105].
* Durée estimée : dix heures (une semaine). [cite_start]Tag final : **v4-tp4**[cite: 106].

## 2. Chiffrement par Master Key
* [cite_start]Une Master Key (fournie par l'administrateur) doit chiffrer les mots de passe avant insertion en base[cite: 107, 111].
* [cite_start]**Règles non négociables** : Pas de stockage en clair, pas de clé dans le code source[cite: 113, 114, 116].
* [cite_start]**Injection** : Uniquement via la variable d'environnement `APP_MASTER_KEY`[cite: 117]. [cite_start]L'application doit refuser de démarrer si elle est absente[cite: 118].
* [cite_start]**Algorithme** : **AES en mode GCM** (chiffrement + intégrité)[cite: 119, 120].
* [cite_start]**Format de stockage** : `v1:Base64(iv):Base64(ciphertext)`[cite: 121, 122, 123].

### 2.1 Processus et Interdictions
* [cite_start]**Inscription** : Chiffrement du mot de passe en clair via `APP_MASTER_KEY` avant stockage dans `password_encrypted`[cite: 127].
* [cite_start]**Login** : Déchiffrement du champ pour recalculer le HMAC[cite: 128].
* [cite_start]**Interdictions strictes** : Pas de clé en dur, pas d'IV fixe (doit être aléatoire), pas de mode ECB, pas de log du mot de passe en clair[cite: 129, 130, 131, 132, 133, 134].
* [cite_start]**Tests Master Key** : Échec si clé absente, round-trip chiffrement/déchiffrement, différence entre clair et chiffré, échec si texte modifié[cite: 135, 136, 137, 138, 139, 140].

---

## 3. GitHub Actions CI/CD
* [cite_start]Automatisation totale : aucun code validé sans pipeline automatique[cite: 141, 143, 144].
* [cite_start]Déclencheurs : **push** sur `main` et **pull request** vers `main`[cite: 145, 149].
* [cite_start]Emplacement : `.github/workflows/ci.yml`[cite: 148].

### [cite_start]3.1 Pipeline minimale attendue [cite: 150, 151, 176]
1. [cite_start]Récupération du code (**checkout**)[cite: 152].
2. [cite_start]Installation **JDK 17** (Temurin)[cite: 153].
3. [cite_start]Injection d'une **Master Key fictive** (`test_master_key_for_ci_only`)[cite: 154, 171, 173].
4. [cite_start]Build et tests via `mvn clean verify`[cite: 155].
5. [cite_start]Analyse SonarCloud via secrets (**SONAR_TOKEN**, **SONAR_PROJECT_KEY**, **SONAR_ORGANIZATION**)[cite: 156, 163, 164].
6. [cite_start]Échec automatique si test échoué ou Quality Gate rouge[cite: 157].

### 3.2 Configuration et Sécurité en CI
* [cite_start]Blocage des merges si la CI échoue[cite: 158, 159, 160].
* [cite_start]Utilisation obligatoire de **H2 en mémoire** pour les tests (indépendance de MySQL)[cite: 165, 166, 167, 168].
* [cite_start]Les secrets ne doivent jamais être exposés dans les logs ou le code[cite: 164, 170].

---

## [cite_start]4. Critères de succès du TP4 [cite: 177]
* [cite_start]Pipeline fonctionnelle à chaque push/PR[cite: 178, 179].
* [cite_start]Tests JUnit réellement exécutés (non simulés) et bloquants[cite: 180, 181].
* [cite_start]Quality Gate SonarCloud vert[cite: 182].
* [cite_start]Secrets jamais commités[cite: 183].
* [cite_start]Chiffrement AES GCM opérationnel avec IV aléatoire[cite: 184].
* [cite_start]L'application crash si `APP_MASTER_KEY` est absente[cite: 185].

[cite_start]**Tag final** : `v4-tp4` (à poser une fois toutes les exigences remplies)[cite: 186, 187, 188].

---

Souhaitez-vous que je vous aide à rédiger la structure du fichier `.github/workflows/ci.yml` ou à implémenter la classe Java pour le chiffrement AES-GCM ?