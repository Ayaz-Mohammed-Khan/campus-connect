package com.campusconnect.userservice.auth;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.Base64;

public final class PemKeyLoader {

    private PemKeyLoader() {}

    // Load private key from path or PEM string
    public static RSAPrivateKey loadPrivateKey(String pemPath, String pemEnv) {
        try {
            String pem = readPem(pemPath, pemEnv);
            return parsePrivateKey(pem);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load RSA private key", e);
        }
    }

    // Load public key
    public static RSAPublicKey loadPublicKey(String pemPath, String pemEnv) {
        try {
            String pem = readPem(pemPath, pemEnv);
            return parsePublicKey(pem);
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

    private static byte[] base64FromPem(String pem) {
        return Base64.getMimeDecoder().decode(
                pem.replaceAll("-----BEGIN (.*)-----", "")
                        .replaceAll("-----END (.*)-----", "")
                        .replaceAll("\\s", "")
        );
    }

    private static RSAPrivateKey parsePrivateKey(String pem) throws Exception {
        byte[] keyBytes = base64FromPem(pem);

        // Try PKCS#8 first
        try {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) kf.generatePrivate(spec);
        } catch (Exception ignore) {
            // Try PKCS#1 -> wrap to PKCS#8
            byte[] pkcs8 = pkcs1ToPkcs8(keyBytes);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) kf.generatePrivate(spec);
        }
    }

    private static RSAPublicKey parsePublicKey(String pem) throws Exception {
        byte[] keyBytes = base64FromPem(pem);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) kf.generatePublic(spec);
    }

    // Convert PKCS#1 to PKCS#8
    private static byte[] pkcs1ToPkcs8(byte[] pkcs1Bytes) {
        // PKCS#1 -> wrap with PKCS#8 header
        // ASN.1 header for RSA PKCS#1 inside PKCS#8:
        final byte[] header = {
                0x30, (byte)0x82, // SEQUENCE
        };
        // Instead of writing ASN.1 builder, easiest approach is to use BouncyCastle in production.
        // For now, try to build minimal PKCS#8 wrapper manually only for typical keys.
        throw new UnsupportedOperationException("PKCS#1 to PKCS#8 conversion not implemented. Use PKCS#8 private key (recommended).");
    }
}
