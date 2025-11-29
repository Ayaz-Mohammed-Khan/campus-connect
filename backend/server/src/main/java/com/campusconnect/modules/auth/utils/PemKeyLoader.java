package com.campusconnect.modules.auth.utils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Pattern;

public final class PemKeyLoader {

    private PemKeyLoader() {}

    // Robust Regex to strip any standard PEM header/footer
    private static final Pattern PEM_HEADER = Pattern.compile("-+BEGIN\\s+.*-+");
    private static final Pattern PEM_FOOTER = Pattern.compile("-+END\\s+.*-+");

    public static RSAPrivateKey loadPrivateKey(String pemPath, String pemEnv) {
        try {
            String pem = readPem(pemPath, pemEnv);
            byte[] encoded = decodePem(pem);
            KeyFactory kf = KeyFactory.getInstance("RSA");

            try {
                // Try Standard PKCS#8
                return (RSAPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
            } catch (Exception e) {
                // Fallback for PKCS#1 (often used in dev) could be added here or handled via OpenSSL conversion
                throw new IllegalStateException("Key format not supported. Ensure key is PKCS#8.", e);
            }
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load RSA private key", e);
        }
    }

    public static RSAPublicKey loadPublicKey(String pemPath, String pemEnv) {
        try {
            String pem = readPem(pemPath, pemEnv);
            byte[] encoded = decodePem(pem);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(encoded));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load RSA public key", e);
        }
    }

    private static String readPem(String path, String env) throws IOException {
        if (path != null && !path.isBlank()) {
            return Files.readString(Path.of(path));
        }
        if (env != null && !env.isBlank()) {
            return env;
        }
        throw new IllegalArgumentException("No PEM path or env provided");
    }

    private static byte[] decodePem(String pem) {
        String content = PEM_HEADER.matcher(pem).replaceAll("");
        content = PEM_FOOTER.matcher(content).replaceAll("");
        content = content.replaceAll("\\s+", "");
        return Base64.getDecoder().decode(content);
    }
}