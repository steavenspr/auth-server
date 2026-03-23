# Auth Server - TP1 → TP3

## Description
Serveur d'authentification réalisé dans le cadre du cours CDWFS.
Ce projet évolue progressivement du TP1 au TP3 en corrigeant les vulnérabilités
à chaque étape.

Stack : Java 17, Spring Boot 3.x, MySQL, Maven

---

## Prérequis
- Java 17
- Maven 3.9
- MySQL (WAMP)

---

## Installation et lancement

1. Cloner le projet :
```bash
git clone https://github.com/steavenspr/auth-server.git
```

2. Créer la base de données MySQL :
```sql
CREATE DATABASE auth_db_tp3;
```

3. Configurer `src/main/resources/application.properties` :
```properties
spring.datasource.url=jdbc:mysql://localhost:3306/auth_db_tp3
spring.datasource.username=root
spring.datasource.password=
smk.secret=${SMK_SECRET}
```

4. Définir la variable d'environnement SMK :
```bash
# Windows (PowerShell)
$env:SMK_SECRET="UneCleDe32CaracteresExactement!!"
```

5. Lancer l'application :
```bash
mvn spring-boot:run
```

---

## Lancer les tests
```bash
mvn test
```

---

## Évolution du projet

### TP1 — Authentification de base
- Stockage mot de passe en clair
- Aucune politique de mot de passe
- Aucune protection brute force

### TP2 — Amélioration du stockage
- Hachage BCrypt des mots de passe
- Politique stricte (12 caractères, majuscule, chiffre, caractère spécial)
- Anti brute force (5 échecs → blocage 2 minutes)
- Qualité logicielle avec SonarCloud (coverage ≥ 80%)
- **Faiblesse restante** : le hash circule encore dans la requête → rejeu possible

### TP3 — Authentification forte (branche actuelle)
- Le mot de passe ne circule plus jamais sur le réseau
- Protocole SSO en un seul échange réseau
- Chiffrement réversible AES avec Server Master Key (SMK)
- HMAC-SHA256 comme preuve d'identité
- Nonce anti-rejeu avec fenêtre de 60 secondes
- Token d'accès avec expiration (15 minutes)

---

## Protocole d'authentification TP3 (HMAC)

### Étape 1 — Le client prépare la preuve
1. Génère un nonce (UUID aléatoire)
2. Prend le timestamp actuel (epoch secondes)
3. Calcule le message : `email + ":" + nonce + ":" + timestamp`
4. Calcule `hmac = HMAC_SHA256(key=password, data=message)`
5. Envoie : `email, nonce, timestamp, hmac`

### Étape 2 — Le serveur vérifie
1. Vérifie que l'email existe → sinon 401
2. Vérifie que le timestamp est dans ±60 secondes → sinon 401
3. Vérifie que le nonce n'a pas déjà été utilisé → sinon 401
4. Déchiffre le mot de passe stocké (AES + SMK)
5. Recalcule le hmac attendu
6. Compare en temps constant → sinon 401
7. Marque le nonce comme consommé
8. Retourne `accessToken` + `expiresAt`

---

## Limites du chiffrement réversible
Ce mécanisme est **pédagogique**. En production on éviterait de stocker
un mot de passe réversible. On préférerait un hash non réversible et adaptatif
comme BCrypt. Ici on accepte le chiffrement réversible pour simplifier
l'apprentissage du protocole signé.

---

## Tableau comparatif TP1 → TP3
| Fonctionnalité | TP1 | TP2 | TP3 |
|----------------|-----|-----|-----|
| Stockage mot de passe | En clair | BCrypt | AES chiffré (réversible) |
| Politique mot de passe | 4 car min | 12 car + règles | 12 car + règles |
| Protection brute force | Aucune | 5 échecs → blocage | 5 échecs → blocage |
| Protocole login | Password en clair | Password haché | HMAC signé |
| Anti-rejeu | Non | Non | Nonce + timestamp |
| Expiration token | Non | Non | 15 minutes |
| SonarCloud | Non | ≥ 80% | ≥ 80% |

---

## SonarCloud
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=steavenspr_auth-server-tp2&metric=alert_status)](https://sonarcloud.io/project/overview?id=steavenspr_auth-server-tp2)