package ms.secureprofile.backend.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;

/**
 * Service responsable de la génération, validation et extraction des JWT (access + refresh).
 */
@Service
public class JwtService {

    private final SecretKey secretKey;
    private final long accessTokenExpirationMs;
    private final long refreshTokenExpirationMs;

    /**
     * Constructeur avec injection des propriétés depuis le .env via spring-dotenv.
     * Toutes les valeurs sont extraites de manière sécurisée.
     */
    public JwtService(
            @Value("${JWT_SECRET}") String jwtSecret,
            @Value("${JWT_ACCESS_EXPIRATION_MS}") long accessTokenExpirationMs,
            @Value("${JWT_REFRESH_EXPIRATION_MS}") long refreshTokenExpirationMs
    ) {
        this.secretKey = Keys.hmacShaKeyFor(jwtSecret.getBytes());
        this.accessTokenExpirationMs = accessTokenExpirationMs;
        this.refreshTokenExpirationMs = refreshTokenExpirationMs;
    }

    /**
     * Génère un JWT court terme (access token) pour l'utilisateur donné.
     */
    public String generateAccessToken(String username) {
        return generateToken(username, accessTokenExpirationMs);
    }

    /**
     * Génère un JWT long terme (refresh token).
     * À stocker côté client ou en base si blacklist ou rotation.
     */
    public String generateRefreshToken(String username) {
        return generateToken(username, refreshTokenExpirationMs);
    }

    /**
     * Génère un JWT signé avec date d'expiration personnalisée.
     */
    private String generateToken(String username, long durationMs) {
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + durationMs))
                .signWith(secretKey)
                .compact();
    }

    /**
     * Extrait le `username` contenu dans le JWT (via `sub`).
     */
    public String extractUsername(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .getSubject();
        } catch (JwtException e) {
            return null; // JWT invalide
        }
    }

    /**
     * Vérifie la validité (signature, expiration, etc.) d'un token.
     */
    public boolean isTokenValid(String token) {
        try {
            Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }
}
