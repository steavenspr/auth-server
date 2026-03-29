# Checklist exhaustive TP3 & TP4

## TP3 — Authentification Forte
- [ ] Protocole HMAC (preuve de connaissance, pas d’envoi du mot de passe)
- [ ] Génération et gestion du nonce (anti-rejeu)
- [ ] Vérification du timestamp (fenêtre ±60s)
- [ ] Comparaison HMAC en temps constant
- [ ] Stockage du mot de passe chiffré (réversible)
- [ ] Utilisation d’une Server Master Key (SMK) pour le chiffrement
- [ ] Table `users` avec champ `password_encrypted`
- [ ] Table `auth_nonce` avec unicité (user_id, nonce), TTL, champ consumed
- [ ] Tests JUnit (≥15, couvrant tous les cas d’usage et d’erreur)
- [ ] Couverture SonarCloud ≥80%
- [ ] JavaDoc pédagogique (hash non réversible en prod)
- [ ] Tags Git demandés (v3.0-start, v3.1-db-nonce, ..., v3-tp3)

## TP4 — Authentification et Master Key
- [ ] Chiffrement AES-GCM (clé injectée, IV aléatoire, pas de clé/IV en dur)
- [ ] Format de stockage : v1:Base64(iv):Base64(ciphertext)
- [ ] Crash si APP_MASTER_KEY absente
- [ ] Inscription : chiffrement du mot de passe avant stockage
- [ ] Login : déchiffrement pour recalculer HMAC
- [ ] Interdiction de clé/IV en dur, pas de mode ECB, pas de log du mot de passe
- [ ] Tests Master Key (échec si clé absente, round-trip, différence clair/chiffré, échec si texte modifié)
- [ ] Pipeline CI/CD GitHub Actions (push sur main, PR vers main)
- [ ] Injection de la clé dans la CI
- [ ] Build, tests, SonarCloud dans la CI
- [ ] Blocage merge si CI échoue
- [ ] Utilisation H2 en mémoire pour les tests
- [ ] Secrets jamais exposés dans logs/code
- [ ] Tag final v4-tp4

---

Je vais maintenant vérifier chaque point dans le projet et compléter ce tableau.
