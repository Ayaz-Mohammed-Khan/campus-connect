package com.campusconnect.modules.auth.services;

import com.campusconnect.modules.auth.utils.PemKeyLoader;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;

/**
 * Service for handling JSON Web Token (JWT) operations using Asymmetric Encryption (RS256).
 * <p>
 * This service loads RSA keys (Private/Public) from the file system or environment variables
 * upon initialization. It configures the {@link NimbusJwtEncoder} for signing tokens and
 * exposes a {@link JwtDecoder} bean for Spring Security's Resource Server.
 *
 * @see com.campusconnect.modules.auth.utils.PemKeyLoader
 */
@Slf4j
@Service
public class JwtService {

    private final JwtEncoder encoder;
    private final JwtDecoder decoder;
    private final long accessTokenSeconds;

    public JwtService(
            @Value("${security.jwt.access-token-ttl-seconds:900}") long accessTokenSeconds,
            @Value("${JWT_PRIVATE_KEY_PATH:}") String privateKeyPath,
            @Value("${JWT_PUBLIC_KEY_PATH:}") String publicKeyPath,
            @Value("${JWT_PRIVATE_KEY:}") String privateKeyPemEnv,
            @Value("${JWT_PUBLIC_KEY:}") String publicKeyPemEnv,
            @Value("${JWT_KID:default-kid}") String kid
    ) {
        this.accessTokenSeconds = accessTokenSeconds;

        // Load RSA keys
        RSAPrivateKey privateKey = PemKeyLoader.loadPrivateKey(privateKeyPath, privateKeyPemEnv);
        RSAPublicKey publicKey = PemKeyLoader.loadPublicKey(publicKeyPath, publicKeyPemEnv);

        // Build JWK for encoder
        RSAKey jwk = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(kid)
                .build();

        // Encoder using JWKSource
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
        this.encoder = new NimbusJwtEncoder(jwkSource);

        // Decoder using public key
        this.decoder = NimbusJwtDecoder.withPublicKey(publicKey).build();
    }

    /**
     * REQUIRED for Spring Security — exposes our decoder to the
     * Resource Server so .jwt() authentication works.
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        return this.decoder;
    }

    /**
     * Generates a short-lived JWT Access Token.
     * <p>
     * Claims included:
     * <ul>
     * <li>{@code sub}: The User UUID.</li>
     * <li>{@code email}: The User email.</li>
     * <li>{@code roles}: List of assigned user roles.</li>
     * </ul>
     *
     * @param userId The unique identifier of the user.
     * @param email  The user's email address.
     * @param roles  The roles assigned to the user.
     * @return A signed JWT string.
     */
    public String generateAccessToken(java.util.UUID userId, String email, List<String> roles) {
        Instant now = Instant.now();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("campus-connect")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(accessTokenSeconds))
                .subject(userId.toString())
                .claim("email", email)
                .claim("roles", roles)
                .build();

        JwsHeader header = JwsHeader.with(org.springframework.security.oauth2.jose.jws.SignatureAlgorithm.RS256)
                .build();

        return encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }

    public Jwt decode(String token) {
        return decoder.decode(token);
    }
}
