package com.securegate.config;

import com.securegate.filter.AlgorithmValidationFilter;
import com.securegate.filter.JwtAuthFilter;
import com.securegate.filter.TokenBlacklistFilter;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Spring Security configuration for SecureGate Nexus.
 *
 * Filter chain order (enforced by @Order on each filter):
 *   1. AlgorithmValidationFilter  — blocks alg=none, HS256/384/512, missing alg
 *   2. TokenBlacklistFilter       — checks Redis for revoked jti
 *   3. JwtAuthFilter              — RSA signature verification, sets SecurityContext
 *
 * Session: STATELESS (no server-side sessions)
 * CSRF: disabled (API-only, JWT-based auth)
 *
 * IMPORTANT: @Order(-10) ensures this SecurityFilterChain takes priority
 * over Spring Boot's default auto-configured security chain.
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

    @PostConstruct
    void init() {
        log.info("=== SecurityConfig LOADED ===");
    }

    private final AlgorithmValidationFilter algorithmValidationFilter;
    private final TokenBlacklistFilter tokenBlacklistFilter;
    private final JwtAuthFilter jwtAuthFilter;

    /**
     * Primary security filter chain with highest priority.
     * @Order(-10) ensures this runs BEFORE Spring Boot's default
     * auto-configured security chain (which uses @Order(0) or higher).
     */
    @Bean
    @Order(-10)
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // CRITICAL: Set security matcher so this chain only handles /api/v1/**
            // This prevents it from conflicting with the default chain
            .securityMatcher("/api/v1/**")

            // Disable CSRF — API-only, no browser forms
            .csrf(csrf -> csrf.disable())

            // Stateless session — no HttpSession, no JSESSIONID cookies
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // Authorization rules
            .authorizeHttpRequests(auth -> auth
                // Public endpoints — no token required (register + login)
                .requestMatchers("/api/v1/auth/register",
                                 "/api/v1/auth/login").permitAll()

                // Admin-only endpoints
                .requestMatchers("/api/v1/users/admin").hasAuthority("ROLE_ADMIN")

                // All other API endpoints require authentication
                .anyRequest().authenticated()
            )

            // Insert custom filters BEFORE UsernamePasswordAuthenticationFilter
            // Order is determined by @Order annotation on each filter class
            .addFilterBefore(algorithmValidationFilter,
                    UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(tokenBlacklistFilter,
                    UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(jwtAuthFilter,
                    UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Prevent Spring Boot from auto-registering our OncePerRequestFilter beans
     * as standalone Servlet Filters. They must ONLY run inside the Spring Security
     * filter chain (added via addFilterBefore above).
     */
    @Bean
    public FilterRegistrationBean<AlgorithmValidationFilter> algFilterRegistration(
            AlgorithmValidationFilter filter) {
        FilterRegistrationBean<AlgorithmValidationFilter> reg = new FilterRegistrationBean<>(filter);
        reg.setEnabled(false);
        return reg;
    }

    @Bean
    public FilterRegistrationBean<TokenBlacklistFilter> blacklistFilterRegistration(
            TokenBlacklistFilter filter) {
        FilterRegistrationBean<TokenBlacklistFilter> reg = new FilterRegistrationBean<>(filter);
        reg.setEnabled(false);
        return reg;
    }

    @Bean
    public FilterRegistrationBean<JwtAuthFilter> jwtFilterRegistration(
            JwtAuthFilter filter) {
        FilterRegistrationBean<JwtAuthFilter> reg = new FilterRegistrationBean<>(filter);
        reg.setEnabled(false);
        return reg;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
