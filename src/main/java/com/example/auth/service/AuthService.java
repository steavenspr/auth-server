package com.example.auth.service;

import com.example.auth.entity.User;
import com.example.auth.exception.AccountLockedException;
import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.exception.InvalidInputException;
import com.example.auth.exception.ResourceConflictException;
import com.example.auth.repository.UserRepository;
import com.example.auth.security.PasswordPolicyValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Service principal gérant la logique d'authentification.
 * <p>
 * TP2 améliore le stockage, mais ne protège pas encore contre le rejeu.
 * Le hash circule encore dans la phase de login et reste rejouable
 * si une requête est capturée. Ce problème sera corrigé au TP3.
 * </p>
 */
@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * Constructeur avec injection du repository et de l'encodeur de mot de passe.
     *
     * @param userRepository  le repository d'accès aux données utilisateur
     * @param passwordEncoder l'encodeur BCrypt pour le hachage des mots de passe
     */
    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Nettoie une chaîne de caractères pour éviter l'injection dans les logs.
     * Supprime les retours à la ligne qui pourraient falsifier les entrées de log.
     *
     * @param input la chaîne à nettoyer
     * @return la chaîne sans retours à la ligne
     */
    private String sanitize(String input) {
        if (input == null) return "";
        return input.replaceAll("[\r\n]", "");
    }

    /**
     * Inscrit un nouvel utilisateur après validation de la politique de mot de passe.
     * Le mot de passe est haché avec BCrypt avant stockage.
     *
     * @param email    l'adresse email de l'utilisateur
     * @param password le mot de passe en clair
     * @return l'utilisateur créé et sauvegardé
     * @throws InvalidInputException     si l'email est invalide ou le mot de passe ne respecte pas la politique
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

        String hashedPassword = passwordEncoder.encode(password);
        User user = new User(email, hashedPassword);
        userRepository.save(user);
        if (logger.isInfoEnabled()) {
            logger.info("Inscription réussie pour : {}", sanitize(email));
        }
        return user;
    }

    /**
     * Authentifie un utilisateur et retourne un token.
     * Vérifie le mot de passe avec BCrypt.
     * Bloque le compte après cinq échecs consécutifs pendant deux minutes.
     *
     * @param email    l'adresse email de l'utilisateur
     * @param password le mot de passe en clair
     * @return le token d'authentification généré
     * @throws AuthenticationFailedException si l'email ou le mot de passe est incorrect
     * @throws AccountLockedException        si le compte est temporairement bloqué
     */
    public String login(String email, String password) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    if (logger.isWarnEnabled()) {
                        logger.warn("Connexion échouée : email inconnu {}", sanitize(email));
                    }
                    return new AuthenticationFailedException("Authentication failed");
                });

        if (user.getLockUntil() != null && user.getLockUntil().isAfter(LocalDateTime.now())) {
            if (logger.isWarnEnabled()) {
                logger.warn("Connexion échouée : compte bloqué pour {}", sanitize(email));
            }
            throw new AccountLockedException("Account is locked. Please try again later.");
        }

        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            user.setFailedAttempts(user.getFailedAttempts() + 1);

            if (user.getFailedAttempts() >= 5) {
                user.setLockUntil(LocalDateTime.now().plusMinutes(2));
                userRepository.save(user);
                if (logger.isWarnEnabled()) {
                    logger.warn("Compte bloqué après 5 échecs pour {}", sanitize(email));
                }
                throw new AccountLockedException("Account is locked. Please try again later.");
            }

            userRepository.save(user);
            if (logger.isWarnEnabled()) {
                logger.warn("Connexion échouée : mauvais mot de passe pour {} ({}/5)",
                        sanitize(email), user.getFailedAttempts());
            }
            throw new AuthenticationFailedException("Authentication failed");
        }

        user.setFailedAttempts(0);
        user.setLockUntil(null);
        String token = UUID.randomUUID().toString();
        user.setToken(token);
        userRepository.save(user);
        if (logger.isInfoEnabled()) {
            logger.info("Connexion réussie pour : {}", sanitize(email));
        }
        return token;
    }

    /**
     * Récupère un utilisateur par son token d'authentification.
     *
     * @param token le token d'authentification
     * @return l'utilisateur correspondant au token
     * @throws AuthenticationFailedException si le token est invalide
     */
    public User getUserByToken(String token) {
        return userRepository.findByToken(token)
                .orElseThrow(() -> new AuthenticationFailedException("Invalid token"));
    }
}