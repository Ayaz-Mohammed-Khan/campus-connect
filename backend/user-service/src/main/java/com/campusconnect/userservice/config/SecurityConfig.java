package com.campusconnect.userservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // PUBLIC endpoints
                        .requestMatchers(
                                "/api/v1/users/health",
                                "/actuator/health",
                                "/actuator/info",
                                "/api/v1/users"          // Allow signup
                        ).permitAll()

                        // PROTECTED endpoints (future JWT)
                        .anyRequest().authenticated()
                )
                // temporary basic auth (will be replaced by JWT later)
                .httpBasic(Customizer.withDefaults());

        return http.build();
    }
}
