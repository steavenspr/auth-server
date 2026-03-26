# README spécial pour IA (TP3 Authentification Forte)

Ce fichier explique l'état du backend Spring Boot pour le TP3, afin que toute IA (ou développeur) puisse comprendre rapidement le contexte, les choix techniques et ce qu'il reste à faire.

## Contexte
- Projet : Authentification forte HMAC (TP3)
- Backend : Spring Boot (Java 17)
- Frontend : Projet séparé (non inclus ici)

## Fonctionnalités déjà en place (backend)
- **Inscription** : /api/auth/register (mot de passe chiffré AES, non hashé)
- **Login** : /api/auth/login (payload JSON, preuve HMAC, anti-rejeu par nonce, timestamp ±60s)
- **Token** : Généré côté serveur, expire en 15 minutes
- **Entités** : User, AuthNonce (anti-rejeu)
- **Sécurité** :
  - Mot de passe chiffré avec AES (clé SMK_SECRET, injectée par variable d'environnement)
  - HMAC-SHA256 pour la preuve de connaissance du secret
  - Nonce unique par login, stocké en base (table auth_nonce)
  - Blocage du compte après 5 échecs
- **Tests** :
  - Utilisation de H2 en mémoire pour les tests
  - Couverture >80% (tests unitaires et d'intégration)
- **Conformité SonarCloud** :
  - Exceptions spécifiques (plus de RuntimeException générique)
  - Complexité cognitive réduite (login refactoré)

## Points importants pour l'IA
- **Ne jamais exposer la clé SMK_SECRET** : elle doit rester dans les variables d'environnement ou secrets GitHub.
- **Le backend attend un payload JSON pour /api/auth/login** (voir DTO LoginRequest).
- **Le frontend doit calculer le HMAC côté client** (Web Crypto API ou équivalent JS) et envoyer le JSON attendu.
- **Le backend ne gère pas le frontend** : le client web est dans un autre projet.
- **Respecter le protocole HMAC du TP3** : email, nonce, timestamp, hmac dans le corps JSON.

## Ce qu'il reste à faire (si besoin)
- Adapter/ajouter des tests si la couverture baisse
- Mettre à jour la documentation si le protocole change
- S'assurer que le frontend respecte bien le protocole (voir README du frontend)

## Pour toute IA ou développeur
- Lis ce fichier avant toute modification ou analyse automatique.
- Si tu dois générer du code, respecte le protocole HMAC et la structure existante.
- Si tu dois faire des tests, utilise le profil "test" (H2, smk.secret de test).

---

**Contact :** steav (ou voir l'historique Git pour les contributeurs)

