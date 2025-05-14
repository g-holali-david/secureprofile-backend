package ms.secureprofile.backend.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import ms.secureprofile.backend.validation.StrongPassword;

import java.time.LocalDateTime;

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Données chiffrées
    @Column(nullable = false, unique = true)
    private String username;

    @NotBlank(message = "Email is required")
    @Column(nullable = false, unique = true)
    private String email;

    // Donnée hachée
    @Column(nullable = false)
    @Size(min = 12, message = "Password must be at least 12 characters")
    @StrongPassword
    private String password;

    // Infos personnelles
    private String firstName;
    private String lastName;

    // Statut du compte
    @Column(name = "is_enabled", nullable = false)
    private boolean isEnabled = true;

    // Timestamps
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    // Rôle (USER, ADMIN)
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "role_id")
    private Role role;

    public User() {}

    public User(String username, String email, String password, String firstName, String lastName, Role role) {
        this.username = username;
        this.email = email;
        this.password = password;
        this.firstName = firstName;
        this.lastName = lastName;
        this.role = role;
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
        this.isEnabled = true;
    }

    // Getters / Setters
    public Long getId() { return id; }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public String getFirstName() { return firstName; }
    public void setFirstName(String firstName) { this.firstName = firstName; }

    public String getLastName() { return lastName; }
    public void setLastName(String lastName) { this.lastName = lastName; }

    public boolean isEnabled() { return isEnabled; }
    public void setEnabled(boolean enabled) { isEnabled = enabled; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }

    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }

    public Role getRole() { return role; }
    public void setRole(Role role) { this.role = role; }
}
