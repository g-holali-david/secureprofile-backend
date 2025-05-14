package ms.secureprofile.backend.service;

import ms.secureprofile.backend.model.RefreshToken;
import ms.secureprofile.backend.model.User;
import ms.secureprofile.backend.repository.RefreshTokenRepository;
import ms.secureprofile.backend.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import ms.secureprofile.backend.repository.BlacklistedTokenRepository;
import ms.secureprofile.backend.model.BlacklistedToken;

import java.time.Instant;

import java.util.Optional;
import java.util.UUID;

/**
 * Gère la création, validation et suppression des refresh tokens côté backend.
 */
@Service
public class RefreshTokenService {

    @Value("${JWT_REFRESH_EXPIRATION_MS}")
    private Long refreshTokenDurationMs;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final BlacklistedTokenRepository blacklistRepo;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository,
                               UserRepository userRepository, BlacklistedTokenRepository blacklistRepo) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.blacklistRepo = blacklistRepo;
    }

    /**
     * Crée un refresh token unique avec une date d'expiration.
     */
    public RefreshToken createRefreshToken(User user) {
        RefreshToken token = new RefreshToken();
        token.setUser(user);
        token.setToken(UUID.randomUUID().toString());
        token.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs)); // ✅ Corrigé ici
        return refreshTokenRepository.save(token);
    }

    /**
     * Vérifie si le token est encore valide.
     * S'il a expiré, il est supprimé, et une exception est levée.
     */
    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().isBefore(Instant.now())) { // ✅ Corrigé ici
            refreshTokenRepository.delete(token);
            throw new RuntimeException("Refresh token expired. Please login again.");
        }
        return token;
    }


    public void blacklistToken(String token) {
        blacklistRepo.save(new BlacklistedToken(token));
    }

    public boolean isBlacklisted(String token) {
        return blacklistRepo.existsByToken(token);
    }

    /**
     * Recherche un refresh token en base par sa valeur.
     */
    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    /**
     * Supprime tous les refresh tokens liés à un utilisateur.
     */
    public int deleteByUser(User user) {
        return refreshTokenRepository.deleteByUser(user);
    }
}
