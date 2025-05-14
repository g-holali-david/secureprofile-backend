package ms.secureprofile.backend.repository;

import ms.secureprofile.backend.model.RefreshToken;
import ms.secureprofile.backend.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);
    int deleteByUser(User user);

    @Modifying
    @Transactional
    void deleteAllByExpiryDateBefore(Instant time);
}
