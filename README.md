# Auth Server - TP2

## Description
Serveur d'authentification réalisé dans le cadre du TP2 CDWFS.
Cette version améliore le TP1 en corrigeant les vulnérabilités majeures :
hachage BCrypt, politique de mot de passe stricte, et anti brute force.

Malgré ces améliorations, l'authentification reste fragile car le secret
circule encore dans la phase de login et reste rejouable si une requête
est capturée. Ce problème sera corrigé au TP3 avec un protocole anti-rejeu.

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
git clone https://github.com/steavenspr/auth-server-tp2.git
```

2. Créer la base de données MySQL :
```sql
CREATE DATABASE auth_db_tp2;
```

3. Configurer `src/main/resources/application.properties` :
```properties
spring.datasource.url=jdbc:mysql://localhost:3306/auth_db_tp2
spring.datasource.username=root
spring.datasource.password=
```

4. Lancer l'application :
```bash
mvn spring-boot:run
```

---

## Objectifs TP2
- Politique de mot de passe stricte (12 caractères, majuscule, chiffre, caractère spécial)
- Hachage BCrypt des mots de passe
- Anti brute force (5 échecs → blocage 2 minutes)
- Route /api/me protégée
- Qualité logicielle avec SonarCloud

---

## Améliorations par rapport au TP1
| Fonctionnalité | TP1 | TP2 |
|---------------|-----|-----|
| Stockage mot de passe | En clair | BCrypt hash |
| Politique mot de passe | 4 caractères min | 12 car, majuscule, chiffre, spécial |
| Protection brute force | Aucune | 5 échecs → blocage 2 min |
| Route /api/me | Non protégée | Protégée par token |

---

## Faiblesse restante
Même avec BCrypt, le hash circule dans la requête de login.
Si un attaquant intercepte la requête, il peut la rejouer.
Ce problème sera corrigé au TP3 avec une clé secrète partagée et un nonce.

---

## Lancer les tests
```bash
mvn test
```