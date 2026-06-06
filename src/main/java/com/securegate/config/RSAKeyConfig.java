package com.securegate.config;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * RSA 2048-bit asymmetric key management.
 * Auto-generates key pair at startup if no keys exist on disk.
 * Provides RSAPublicKey for JWT verification and RSAPrivateKey for JWT signing.
 *
 * SECURITY: Never uses hardcoded secrets. All keys are 2048-bit RSA.
 */
@Configuration
@Slf4j
public class RSAKeyConfig {

    @Value("${jwt.keys-dir:keys}")
    private String keysDir;

    @Value("${jwt.private-key-path:keys/private.pem}")
    private String privateKeyPathStr;

    @Value("${jwt.public-key-path:keys/public.pem}")
    private String publicKeyPathStr;

    @Getter
    private RSAPublicKey publicKey;

    @Getter
    private RSAPrivateKey privateKey;

    private static final int KEY_SIZE = 2048;
    private static final String KEY_ALGORITHM = "RSA";

    private static final String PRIVATE_KEY_HEADER = "-----BEGIN PRIVATE KEY-----";
    private static final String PRIVATE_KEY_FOOTER = "-----END PRIVATE KEY-----";
    private static final String PUBLIC_KEY_HEADER = "-----BEGIN PUBLIC KEY-----";
    private static final String PUBLIC_KEY_FOOTER = "-----END PUBLIC KEY-----";

    @PostConstruct
    public void init() throws Exception {
        Path privateKeyPath = Path.of(privateKeyPathStr);
        Path publicKeyPath = Path.of(publicKeyPathStr);
        Path keysDirectory = Path.of(keysDir);

        if (Files.exists(privateKeyPath) && Files.exists(publicKeyPath)) {
            log.info("RSA keys found on disk. Loading existing keys...");
            loadKeys(privateKeyPath, publicKeyPath);
        } else {
            log.info("RSA keys not found. Generating new 2048-bit RSA key pair...");
            Files.createDirectories(keysDirectory);
            KeyPair keyPair = generateKeyPair();
            writeKeysToDisk(keyPair, privateKeyPath, publicKeyPath);
            this.privateKey = (RSAPrivateKey) keyPair.getPrivate();
            this.publicKey = (RSAPublicKey) keyPair.getPublic();
        }

        log.info("RSA key management initialized. Public key algorithm: {}",
                publicKey.getAlgorithm());
    }

    @Bean
    public RSAPublicKey rsaPublicKey() {
        return this.publicKey;
    }

    @Bean
    public RSAPrivateKey rsaPrivateKey() {
        return this.privateKey;
    }

    // ──────────────────────────────────────────────
    // Internal helpers
    // ──────────────────────────────────────────────

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        generator.initialize(KEY_SIZE);
        return generator.generateKeyPair();
    }

    private void loadKeys(Path privateKeyPath, Path publicKeyPath) throws Exception {
        String privateContent = Files.readString(privateKeyPath);
        String publicContent = Files.readString(publicKeyPath);

        byte[] privateBytes = decodePem(privateContent, PRIVATE_KEY_HEADER, PRIVATE_KEY_FOOTER);
        byte[] publicBytes = decodePem(publicContent, PUBLIC_KEY_HEADER, PUBLIC_KEY_FOOTER);

        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        this.privateKey = (RSAPrivateKey) keyFactory.generatePrivate(
                new PKCS8EncodedKeySpec(privateBytes));
        this.publicKey = (RSAPublicKey) keyFactory.generatePublic(
                new X509EncodedKeySpec(publicBytes));
    }

    private void writeKeysToDisk(KeyPair keyPair, Path privatePath, Path publicPath)
            throws Exception {
        String privatePem = encodePem(keyPair.getPrivate().getEncoded(),
                PRIVATE_KEY_HEADER, PRIVATE_KEY_FOOTER);
        String publicPem = encodePem(keyPair.getPublic().getEncoded(),
                PUBLIC_KEY_HEADER, PUBLIC_KEY_FOOTER);

        Files.writeString(privatePath, privatePem);
        Files.writeString(publicPath, publicPem);
        log.info("RSA keys written to: {} and {}", privatePath, publicPath);
    }

    private String encodePem(byte[] der, String header, String footer) {
        StringBuilder sb = new StringBuilder();
        sb.append(header).append('\n');
        String encoded = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
        sb.append(encoded);
        if (!encoded.endsWith("\n")) {
            sb.append('\n');
        }
        sb.append(footer).append('\n');
        return sb.toString();
    }

    private byte[] decodePem(String pem, String header, String footer) {
        String stripped = pem
                .replace(header, "")
                .replace(footer, "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(stripped);
    }
}
