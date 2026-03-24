package com.example.auth.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Entité représentant un utilisateur dans la base de données.
 * TP3 : mot de passe chiffré AES (réversible) avec Server Master Key,
 * nécessaire pour recalculer le HMAC côté serveur.
 * Token d'accès avec expiration de 15 minutes.
 */
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String email;

    @Column(name = "password_encrypted")
    private String passwordEncrypted;

    private String token;

    @Column(name = "token_expires_at")
    private LocalDateTime tokenExpiresAt;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private int failedAttempts = 0;

    @Column(name = "lock_until")
    private LocalDateTime lockUntil;

    /**
     * Constructeur par défaut requis par JPA.
     */
    public User() {}

    /**
     * Constructeur principal.
     *
     * @param email             l'adresse email de l'utilisateur
     * @param passwordEncrypted le mot de passe chiffré avec AES
     */
    public User(String email, String passwordEncrypted) {
        this.email = email;
        this.passwordEncrypted = passwordEncrypted;
        this.createdAt = LocalDateTime.now();
        this.failedAttempts = 0;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getPasswordEncrypted() { return passwordEncrypted; }
    public void setPasswordEncrypted(String passwordEncrypted) { this.passwordEncrypted = passwordEncrypted; }

    public String getToken() { return token; }
    public void setToken(String token) { this.token = token; }

    public LocalDateTime getTokenExpiresAt() { return tokenExpiresAt; }
    public void setTokenExpiresAt(LocalDateTime tokenExpiresAt) { this.tokenExpiresAt = tokenExpiresAt; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }

    public int getFailedAttempts() { return failedAttempts; }
    public void setFailedAttempts(int failedAttempts) { this.failedAttempts = failedAttempts; }

    public LocalDateTime getLockUntil() { return lockUntil; }
    public void setLockUntil(LocalDateTime lockUntil) { this.lockUntil = lockUntil; }
}