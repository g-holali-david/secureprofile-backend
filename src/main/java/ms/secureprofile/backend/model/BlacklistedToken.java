package ms.secureprofile.backend.model;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "blacklisted_tokens")
public class BlacklistedToken {
    @Id
    private String token;

    private Instant blacklistedAt;

    public BlacklistedToken() {}

    public BlacklistedToken(String token) {
        this.token = token;
        this.blacklistedAt = Instant.now();
    }

    public String getToken() { return token; }
    public Instant getBlacklistedAt() { return blacklistedAt; }
}
