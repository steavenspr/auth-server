package com.example.auth.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Configuration de Spring Security.
 * Désactive la protection par défaut car l'authentification
 * est gérée manuellement via token.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Désactive la sécurité par défaut de Spring Security
     * et autorise tous les endpoints.
     *
     * @param http la configuration HTTP de Spring Security
     * @return la chaîne de filtres configurée
     * @throws Exception si la configuration échoue
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .anyRequest().permitAll()
            );
        return http.build();
    }

    /**
     * Bean BCryptPasswordEncoder pour le hachage des mots de passe.
     *
     * @return l'encodeur de mot de passe BCrypt
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}