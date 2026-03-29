package com.example.auth.controller;

import com.example.auth.entity.User;
import com.example.auth.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.ChangePasswordRequest;

import java.util.Map;

/**
 * Contrôleur REST gérant les endpoints d'authentification TP3.
 * Le login accepte désormais une preuve HMAC au lieu d'un mot de passe.
 */
@RestController
@RequestMapping("/api")
public class AuthController {

    private final AuthService authService;

    /**
     * Constructeur avec injection du service d'authentification.
     *
     * @param authService le service principal d'authentification
     */
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * Inscrit un nouvel utilisateur.
     *
     * @param email    l'adresse email de l'utilisateur
     * @param password le mot de passe en clair
     * @return message de confirmation
     */
    @PostMapping("/auth/register")
    public String register(@RequestParam String email,
                           @RequestParam String password) {
        authService.register(email, password);
        return "User registered";
    }

    /**
     * Authentifie un utilisateur via le protocole HMAC.
     * Le mot de passe ne circule plus — seule la preuve HMAC est envoyée.
     *
     * @param request le payload JSON contenant email, nonce, timestamp, hmac
     * @return token d'accès et date d'expiration
     */
    @PostMapping("/auth/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody LoginRequest request) {
        String token = authService.login(
                request.getEmail(),
                request.getNonce(),
                request.getTimestamp(),
                request.getHmac()
        );
        User user = authService.getUserByToken(token);
        return ResponseEntity.ok(Map.of(
                "accessToken", token,
                "expiresAt", user.getTokenExpiresAt().toString()
        ));
    }

    /**
     * Retourne les informations de l'utilisateur authentifié.
     * Le token doit être valide et non expiré.
     *
     * @param token le token d'accès
     * @return message de bienvenue avec l'email de l'utilisateur
     */
    @GetMapping("/me")
    public String me(@RequestParam String token) {
        User user = authService.getUserByToken(token);
        return "Bienvenue " + user.getEmail();
    }

    /**
     * Change le mot de passe d'un utilisateur authentifié.
     *
     * @param request le payload JSON contenant email, oldPassword, newPassword, confirmPassword
     * @return message de confirmation
     */
    @PutMapping("/auth/change-password")
    public ResponseEntity<String> changePassword(@RequestBody ChangePasswordRequest request) {
        authService.changePassword(request);
        return ResponseEntity.ok("Password changed successfully");
    }
}