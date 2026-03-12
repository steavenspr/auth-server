package com.example.auth.service;

import com.example.auth.entity.User;
import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.exception.InvalidInputException;
import com.example.auth.exception.ResourceConflictException;
import com.example.auth.repository.UserRepository;
import com.example.auth.security.PasswordPolicyValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.UUID;

/**
 * Service principal gérant la logique d'authentification.
 * <p>
 * TP2 améliore le stockage mais ne protège pas encore contre le rejeu.
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
            logger.warn("Inscription échouée : format email invalide pour {}", email);
            throw new InvalidInputException("Invalid email format");
        }

        PasswordPolicyValidator.validate(password);

        if (userRepository.findByEmail(email).isPresent()) {
            logger.warn("Inscription échouée : email déjà existant pour {}", email);
            throw new ResourceConflictException("Email already exists");
        }

        // Hachage du mot de passe avec BCrypt avant stockage
        String hashedPassword = passwordEncoder.encode(password);
        User user = new User(email, hashedPassword);
        userRepository.save(user);
        logger.info("Inscription réussie pour : {}", email);
        return user;
    }

    /**
     * Authentifie un utilisateur et retourne un token.
     * Vérifie le mot de passe avec BCrypt.
     *
     * @param email    l'adresse email de l'utilisateur
     * @param password le mot de passe en clair
     * @return le token d'authentification généré
     * @throws AuthenticationFailedException si l'email ou le mot de passe est incorrect
     */
    public String login(String email, String password) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    logger.warn("Connexion échouée : email inconnu {}", email);
                    return new AuthenticationFailedException("Email not found");
                });

        // Vérification du mot de passe avec BCrypt
        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            logger.warn("Connexion échouée : mauvais mot de passe pour {}", email);
            throw new AuthenticationFailedException("Invalid password");
        }

        String token = UUID.randomUUID().toString();
        user.setToken(token);
        userRepository.save(user);
        logger.info("Connexion réussie pour : {}", email);
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