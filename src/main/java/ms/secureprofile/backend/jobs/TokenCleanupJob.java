package ms.secureprofile.backend.jobs;

import jakarta.transaction.Transactional;
import ms.secureprofile.backend.repository.RefreshTokenRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
public class TokenCleanupJob {
    private final RefreshTokenRepository refreshTokenRepository;

    public TokenCleanupJob(RefreshTokenRepository repo) {
        this.refreshTokenRepository = repo;
    }

    @Scheduled(cron = "0 0 * * * *") // Chaque heure
    @Transactional
    public void deleteExpiredTokens() {
        refreshTokenRepository.deleteAllByExpiryDateBefore(Instant.now());
    }

}
