package com.campusconnect.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.*;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Spring Security Configuration for a Stateless Resource Server.
 * <p>
 * Configures the {@link SecurityFilterChain} to:
 * <ul>
 * <li>Disable CSRF (not needed for stateless APIs).</li>
 * <li>Enforce {@link SessionCreationPolicy#STATELESS}.</li>
 * <li>Configure public vs. protected endpoints.</li>
 * <li>Integrate OAuth2 Resource Server for JWT validation.</li>
 * </ul>
 */
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Defines the HTTP security filter chain.
     * <p>
     * <b>Public Endpoints:</b>
     * <ul>
     * <li>Actuator Health/Info</li>
     * <li>Auth routes ({@code /auth/**})</li>
     * <li>User Registration (POST {@code /api/v1/users})</li>
     * </ul>
     *
     * @param http The HttpSecurity builder.
     * @return The built filter chain.
     * @throws Exception if configuration fails.
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // 1. Static & Health (Public)
                        .requestMatchers(
                                "/actuator/health",
                                "/actuator/info",
                                "/api/v1/users/health"
                        ).permitAll()

                        // 2. Auth Endpoints (Public)
                        .requestMatchers("/auth/**").permitAll()

                        // 3. User Registration (POST Public / GET Secured)
                        .requestMatchers(HttpMethod.POST, "/api/v1/users").permitAll()

                        // 4. Default: Everything else requires Authentication
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth -> oauth.jwt(Customizer.withDefaults()));

        return http.build();
    }
}