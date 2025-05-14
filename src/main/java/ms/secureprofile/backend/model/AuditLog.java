package ms.secureprofile.backend.model;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "audit_log")
public class AuditLog {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;
    private String action;
    private Instant timestamp;
    private String ipAddress;

    public AuditLog() {}

    public AuditLog(String username, String action, String ipAddress) {
        this.username = username;
        this.action = action;
        this.timestamp = Instant.now();
        this.ipAddress = ipAddress;
    }

    // Getters and Setters
    public Long getId() { return id; }
    public String getUsername() { return username; }
    public String getAction() { return action; }
    public Instant getTimestamp() { return timestamp; }
    public String getIpAddress() { return ipAddress; }

    public void setId(Long id) {
        this.id = id;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public void setAction(String action) {
        this.action = action;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }
}
