package com.example.auth.service;

import com.example.auth.entity.AuthNonce;
import com.example.auth.entity.User;
import com.example.auth.exception.AccountLockedException;
import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.exception.InvalidInputException;
import com.example.auth.exception.ResourceConflictException;
import com.example.auth.repository.AuthNonceRepository;
import com.example.auth.repository.UserRepository;
import com.example.auth.security.AesEncryptionService;
import com.example.auth.security.HmacService;
import com.example.auth.security.PasswordPolicyValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Service principal gérant la logique d'authentification.
 * <p>
 * TP3 — Authentification forte par protocole HMAC signé.
 * Le mot de passe ne circule plus sur le réseau.
 * Le client prouve qu'il connaît le secret en calculant une signature HMAC.
 * Protection anti-rejeu par nonce unique et fenêtre timestamp de ±60 secondes.
 * </p>
 * <p>
 * Limite pédagogique : le chiffrement AES est réversible.
 * En production on utiliserait un hash non réversible et adaptatif.
 * </p>
 */
@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);
    private static final long TIMESTAMP_WINDOW_SECONDS = 60;
    private static final long TOKEN_EXPIRY_MINUTES = 15;
    private static final long NONCE_TTL_SECONDS = 120;

    private final UserRepository userRepository;
    private final AuthNonceRepository nonceRepository;
    private final AesEncryptionService aesEncryptionService;
    private final HmacService hmacService;

    /**
     * Constructeur avec injection des dépendances.
     *
     * @param userRepository       le repository d'accès aux utilisateurs
     * @param nonceRepository      le repository d'accès aux nonces
     * @param aesEncryptionService le service de chiffrement AES
     * @param hmacService          le service de calcul HMAC
     */
    public AuthService(UserRepository userRepository,
                       AuthNonceRepository nonceRepository,
                       AesEncryptionService aesEncryptionService,
                       HmacService hmacService) {
        this.userRepository = userRepository;
        this.nonceRepository = nonceRepository;
        this.aesEncryptionService = aesEncryptionService;
        this.hmacService = hmacService;
    }

    /**
     * Nettoie une chaîne pour éviter l'injection dans les logs.
     *
     * @param input la chaîne à nettoyer
     * @return la chaîne sans retours à la ligne
     */
    private String sanitize(String input) {
        if (input == null) return "";
        return input.replaceAll("[\r\n]", "");
    }

    /**
     * Inscrit un nouvel utilisateur.
     * Le mot de passe est chiffré avec AES pour permettre
     * la vérification HMAC ultérieure.
     *
     * @param email    l'adresse email de l'utilisateur
     * @param password le mot de passe en clair
     * @return l'utilisateur créé
     * @throws InvalidInputException     si l'email ou le mot de passe est invalide
     * @throws ResourceConflictException si l'email existe déjà
     */
    public User register(String email, String password) {
        if (email == null || email.isEmpty()) {
            logger.warn("Inscription échouée : email vide");
            throw new InvalidInputException("Email cannot be empty");
        }
        if (!email.contains("@")) {
            if (logger.isWarnEnabled()) {
                logger.warn("Inscription échouée : format email invalide pour {}", sanitize(email));
            }
            throw new InvalidInputException("Invalid email format");
        }

        PasswordPolicyValidator.validate(password);

        if (userRepository.findByEmail(email).isPresent()) {
            if (logger.isWarnEnabled()) {
                logger.warn("Inscription échouée : email déjà existant pour {}", sanitize(email));
            }
            throw new ResourceConflictException("Email already exists");
        }

        String encryptedPassword = aesEncryptionService.encrypt(password);
        User user = new User(email, encryptedPassword);
        userRepository.save(user);
        if (logger.isInfoEnabled()) {
            logger.info("Inscription réussie pour : {}", sanitize(email));
        }
        return user;
    }

    /**
     * Authentifie un utilisateur via le protocole HMAC.
     * Vérifie dans l'ordre : email, timestamp, nonce, signature HMAC.
     * Le nonce est réservé immédiatement après vérification pour bloquer
     * tout rejeu simultané, puis marqué consommé après validation HMAC.
     * Retourne un token d'accès valide 15 minutes.
     *
     * @param email     l'adresse email de l'utilisateur
     * @param nonce     un UUID aléatoire généré par le client
     * @param timestamp le timestamp epoch en secondes
     * @param hmac      la signature HMAC-SHA256 calculée par le client
     * @return le token d'accès généré
     * @throws AuthenticationFailedException si la vérification échoue
     * @throws AccountLockedException        si le compte est bloqué
     */
    public String login(String email, String nonce, long timestamp, String hmac) {
        User user = getUserOrFail(email);
        checkLockout(user, email);
        checkTimestampWindow(timestamp, email);
        checkNonceNotUsed(user, nonce, email);

        // Réserver le nonce immédiatement (consumed = false)
        AuthNonce authNonce = new AuthNonce(
                user, nonce,
                LocalDateTime.now().plusSeconds(NONCE_TTL_SECONDS)
        );
        authNonce.setConsumed(false);
        nonceRepository.save(authNonce);

        // Déchiffrer le mot de passe et recalculer le HMAC
        String passwordPlain = aesEncryptionService.decrypt(user.getPasswordEncrypted());
        String message = email + ":" + nonce + ":" + timestamp;
        String expectedHmac = hmacService.compute(passwordPlain, message);
        handleFailedHmac(user, expectedHmac, hmac);

        // Marquer le nonce comme consommé
        authNonce.setConsumed(true);
        nonceRepository.save(authNonce);

        // Générer le token avec expiration
        user.setFailedAttempts(0);
        user.setLockUntil(null);
        String token = UUID.randomUUID().toString();
        user.setToken(token);
        user.setTokenExpiresAt(LocalDateTime.now().plusMinutes(TOKEN_EXPIRY_MINUTES));
        userRepository.save(user);

        if (logger.isInfoEnabled()) {
            logger.info("Connexion réussie pour : {}", sanitize(email));
        }
        return token;
    }

    private User getUserOrFail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    if (logger.isWarnEnabled()) {
                        logger.warn("Connexion échouée : email inconnu {}", sanitize(email));
                    }
                    return new AuthenticationFailedException("Authentication failed");
                });
    }

    private void checkLockout(User user, String email) {
        if (user.getLockUntil() != null && user.getLockUntil().isAfter(LocalDateTime.now())) {
            if (logger.isWarnEnabled()) {
                logger.warn("Connexion échouée : compte bloqué pour {}", sanitize(email));
            }
            throw new AccountLockedException("Account is locked. Please try again later.");
        }
    }

    private void checkTimestampWindow(long timestamp, String email) {
        long now = Instant.now().getEpochSecond();
        if (Math.abs(now - timestamp) > TIMESTAMP_WINDOW_SECONDS) {
            if (logger.isWarnEnabled()) {
                logger.warn("Connexion échouée : timestamp hors fenêtre pour {}", sanitize(email));
            }
            throw new AuthenticationFailedException("Authentication failed");
        }
    }

    private void checkNonceNotUsed(User user, String nonce, String email) {
        if (nonceRepository.findByUserAndNonce(user, nonce).isPresent()) {
            if (logger.isWarnEnabled()) {
                logger.warn("Connexion échouée : nonce déjà utilisé pour {}", sanitize(email));
            }
            throw new AuthenticationFailedException("Authentication failed");
        }
    }

    private void handleFailedHmac(User user, String expectedHmac, String hmac) {
        if (!hmacService.verifyConstantTime(expectedHmac, hmac)) {
            user.setFailedAttempts(user.getFailedAttempts() + 1);
            if (user.getFailedAttempts() >= 5) {
                user.setLockUntil(LocalDateTime.now().plusMinutes(2));
                userRepository.save(user);
                throw new AccountLockedException("Account is locked. Please try again later.");
            }
            userRepository.save(user);
            throw new AuthenticationFailedException("Authentication failed");
        }
    }

    /**
     * Récupère un utilisateur par son token d'accès valide.
     * Vérifie que le token n'est pas expiré.
     *
     * @param token le token d'accès
     * @return l'utilisateur correspondant
     * @throws AuthenticationFailedException si le token est invalide ou expiré
     */
    public User getUserByToken(String token) {
        User user = userRepository.findByToken(token)
                .orElseThrow(() -> new AuthenticationFailedException("Invalid token"));

        if (user.getTokenExpiresAt() == null ||
                user.getTokenExpiresAt().isBefore(LocalDateTime.now())) {
            throw new AuthenticationFailedException("Token expired");
        }
        return user;
    }
}