package ms.secureprofile.backend.security;

import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service pour limiter les tentatives de connexion par utilisateur.
 */
@Service
public class LoginAttemptService {

    private static final int MAX_ATTEMPTS = 5;
    private static final long BLOCK_DURATION_MS = 15 * 60 * 1000; // 15 minutes

    // Map des tentatives échouées : username → [nombre, timestamp dernier échec]
    private final Map<String, Integer> attempts = new ConcurrentHashMap<>();
    private final Map<String, Instant> blockedUntil = new ConcurrentHashMap<>();

    @PostConstruct
    public void init() {
        // Optionnel : tâche planifiée de nettoyage si besoin
    }

    public void loginFailed(String username) {
        int tries = attempts.getOrDefault(username, 0);
        attempts.put(username, tries + 1);

        if (tries + 1 >= MAX_ATTEMPTS) {
            blockedUntil.put(username, Instant.now().plusMillis(BLOCK_DURATION_MS));
        }
    }

    public void loginSucceeded(String username) {
        attempts.remove(username);
        blockedUntil.remove(username);
    }

    public boolean isBlocked(String username) {
        Instant blocked = blockedUntil.get(username);
        if (blocked == null) return false;
        if (blocked.isBefore(Instant.now())) {
            // Expiré → déblocage automatique
            blockedUntil.remove(username);
            attempts.remove(username);
            return false;
        }
        return true;
    }

    public long remainingBlockSeconds(String username) {
        Instant blocked = blockedUntil.get(username);
        if (blocked == null) return 0;
        return Math.max(0, blocked.getEpochSecond() - Instant.now().getEpochSecond());
    }
}
