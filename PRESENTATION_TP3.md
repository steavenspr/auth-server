# Présentation du TP3 – Authentification forte

## 1. Introduction

Ce TP3 vise à mettre en place une authentification forte où le mot de passe ne circule jamais sur le réseau, même sous forme hachée. L’objectif est de prouver la connaissance d’un secret sans jamais le transmettre, en s’appuyant sur un protocole sécurisé utilisant HMAC, nonce, timestamp et une clé secrète partagée.

---

## 2. Architecture générale

- **Stack** : Java 17, Spring Boot 3.x, MySQL, Maven
- **Sécurité** : Mot de passe chiffré (AES + SMK), HMAC, nonce, timestamp, anti-rejeu
- **Qualité** : Tests JUnit, SonarCloud (≥80%), CI/CD

---

## 3. Protocole d’authentification (vue d’ensemble)

### a. Côté client
1. L’utilisateur saisit son email et son mot de passe.
2. Le client génère un nonce (UUID) et récupère le timestamp actuel (epoch secondes).
3. Il construit le message : `email:nonce:timestamp`.
4. Il calcule le HMAC_SHA256 avec le mot de passe comme clé.
5. Il envoie un POST `/api/auth/login` avec :
   ```json
   {
     "email": "...",
     "nonce": "...",
     "timestamp": ...,
     "hmac": "..."
   }
   ```

### b. Côté serveur
1. Vérifie l’existence de l’email (401 sinon).
2. Vérifie la fenêtre du timestamp (±60s, sinon 401).
3. Vérifie que le nonce n’a pas déjà été utilisé (anti-rejeu, sinon 401).
4. Déchiffre le mot de passe (AES + SMK).
5. Reconstruit le message et recalcule le HMAC attendu.
6. Compare en temps constant (401 si différent).
7. Marque le nonce comme consommé.
8. Émet un accessToken (valide 15 min) et l’envoie au client.

---

## 4. Structure de la base de données

- **users** : id, email, password_encrypted, created_at
- **auth_nonce** : id, user_id, nonce, expires_at, consumed, created_at, unicité (user_id, nonce)

---

## 5. Explication du code (exemples clés)

### a. Génération du HMAC côté client (pseudo-code)
```java
String nonce = UUID.randomUUID().toString();
long timestamp = Instant.now().getEpochSecond();
String message = email + ":" + nonce + ":" + timestamp;
String hmac = HmacUtils.hmacSha256Hex(password, message);
// Envoi du JSON { email, nonce, timestamp, hmac }
```

### b. Vérification côté serveur (extrait Java/Spring)
```java
// 1. Vérifier l’email
User user = userRepository.findByEmail(email);
if (user == null) throw new UnauthorizedException();

// 2. Vérifier le timestamp
if (Math.abs(now - timestamp) > 60) throw new UnauthorizedException();

// 3. Vérifier le nonce
if (authNonceRepository.existsByUserIdAndNonce(user.getId(), nonce)) throw new UnauthorizedException();

// 4. Déchiffrer le mot de passe
String password = decrypt(user.getPasswordEncrypted(), smk);

// 5. Recalculer le HMAC
String message = email + ":" + nonce + ":" + timestamp;
String hmacExpected = HmacUtils.hmacSha256Hex(password, message);

// 6. Comparaison en temps constant
if (!MessageDigest.isEqual(hmacExpected.getBytes(), hmacReceived.getBytes())) throw new UnauthorizedException();

// 7. Marquer le nonce comme consommé
// ...

// 8. Générer et retourner le token
// ...
```

---

## 6. Sécurité et limites
- Aucun mot de passe ne circule sur le réseau.
- Le timestamp limite la fenêtre d’attaque.
- Le nonce empêche le rejeu.
- Le chiffrement réversible est **uniquement pédagogique** (voir README).

---

## 7. Tests et qualité
- ≥15 tests JUnit couvrant tous les cas (login OK/KO, timestamp, nonce, user inconnu, token, accès API, etc.).
- Couverture SonarCloud ≥80%.
- CI/CD avec analyse automatique à chaque push.

---

## 8. Conseils pour l’oral
- Utiliser un schéma pour illustrer le protocole (client/serveur).
- Montrer un exemple de requête et de réponse.
- Expliquer chaque étape et sa justification en sécurité.
- Mettre en avant la rigueur des tests et la qualité du code.
- Préciser le caractère pédagogique du chiffrement réversible.

---

## 9. Conclusion
Ce TP3 démontre la mise en place d’un protocole d’authentification forte, sécurisé et pédagogique, en respectant les bonnes pratiques de développement et de sécurité.

