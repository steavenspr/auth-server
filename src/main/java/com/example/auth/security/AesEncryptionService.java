package com.example.auth.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Service de chiffrement AES symétrique.
 * Utilise AES/GCM/NoPadding avec une Server Master Key (SMK).
 * Le mot de passe est chiffré de façon réversible pour permettre
 * au serveur de recalculer le HMAC lors de l'authentification.
 *
 * Limite pédagogique : en production on éviterait le chiffrement
 * réversible — on préférerait un hash non réversible et adaptatif.
 */
@Service
public class AesEncryptionService {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int IV_SIZE = 12; // GCM recommande 12 octets

    private final SecretKeySpec secretKey;

    /**
     * Constructeur — initialise la clé AES depuis la variable d'environnement SMK_SECRET.
     * La clé doit faire exactement 32 caractères (256 bits).
     *
     * @param smkSecret la clé secrète maître injectée depuis application.properties
     */
    public AesEncryptionService(@Value("${smk.secret}") String smkSecret) {
        byte[] keyBytes = smkSecret.getBytes(StandardCharsets.UTF_8);
        byte[] key32 = new byte[32];
        System.arraycopy(keyBytes, 0, key32, 0, Math.min(keyBytes.length, 32));
        this.secretKey = new SecretKeySpec(key32, "AES");
    }

    /**
     * Chiffre une chaîne en clair avec AES.
     * L'IV aléatoire est préfixé au résultat chiffré.
     *
     * @param plainText le texte en clair à chiffrer
     * @return Base64(IV + données chiffrées)
     */
    public String encrypt(String plainText) {
        try {
            byte[] iv = new byte[IV_SIZE];
            new SecureRandom().nextBytes(iv);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv); // 128 bits tag

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
            byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            byte[] combined = new byte[IV_SIZE + encrypted.length];
            System.arraycopy(iv, 0, combined, 0, IV_SIZE);
            System.arraycopy(encrypted, 0, combined, IV_SIZE, encrypted.length);

            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            throw new RuntimeException("Erreur de chiffrement AES", e);
        }
    }

    /**
     * Déchiffre une chaîne chiffrée avec AES.
     *
     * @param encryptedText Base64(IV + données chiffrées)
     * @return le texte en clair
     */
    public String decrypt(String encryptedText) {
        try {
            byte[] combined = Base64.getDecoder().decode(encryptedText);

            byte[] iv = new byte[IV_SIZE];
            byte[] encrypted = new byte[combined.length - IV_SIZE];
            System.arraycopy(combined, 0, iv, 0, IV_SIZE);
            System.arraycopy(combined, IV_SIZE, encrypted, 0, encrypted.length);

            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);

            return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Erreur de déchiffrement AES", e);
        }
    }
}