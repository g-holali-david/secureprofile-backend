package ms.secureprofile.backend.service;

import ms.secureprofile.backend.model.Role;
import ms.secureprofile.backend.model.User;
import ms.secureprofile.backend.repository.RoleRepository;
import ms.secureprofile.backend.repository.UserRepository;
import ms.secureprofile.backend.security.EncryptService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final EncryptService encryptService;

    public UserService(UserRepository userRepository,
                       RoleRepository roleRepository,
                       PasswordEncoder passwordEncoder,
                       EncryptService encryptService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.encryptService = encryptService;
    }

    public User register(User user) {

        if (userRepository.existsByEmail(encryptService.encrypt(user.getEmail()))) {
            throw new RuntimeException("Email already in use");
        }
        // idem pour username si besoin
        if (userRepository.existsByUsername(encryptService.encrypt(user.getUsername()))) {
            throw new RuntimeException("Username already in use");
        }
        user.setUsername(encryptService.encrypt(user.getUsername()));
        user.setEmail(encryptService.encrypt(user.getEmail()));
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRole(roleRepository.findByName("USER").orElseThrow());
        user.setEnabled(true);
        return userRepository.save(user);
    }

    public User getByUsername(String rawUsername) {
        String encrypted = encryptService.encrypt(rawUsername);
        return userRepository.findByUsername(encrypted)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

    public void updateUserProfile(String rawUsername, Map<String, String> updates) {
        User user = getByUsername(rawUsername);
        if (updates.containsKey("firstName")) user.setFirstName(updates.get("firstName"));
        if (updates.containsKey("lastName")) user.setLastName(updates.get("lastName"));
        userRepository.save(user);
    }

    public void changePassword(String rawUsername, String oldPwd, String newPwd) {
        User user = getByUsername(rawUsername);
        if (!passwordEncoder.matches(oldPwd, user.getPassword())) {
            throw new RuntimeException("Incorrect current password");
        }
        user.setPassword(passwordEncoder.encode(newPwd));
        userRepository.save(user);
    }

    public void deleteByUsername(String rawUsername) {
        User user = getByUsername(rawUsername);
        userRepository.delete(user);
    }

    public ResponseEntity<?> deleteById(Long id) {
        if (!userRepository.existsById(id)) return ResponseEntity.notFound().build();
        userRepository.deleteById(id);
        return ResponseEntity.ok(Map.of("message", "User deleted"));
    }

    public ResponseEntity<User> searchByUsername(String username) {
        String encrypted = encryptService.encrypt(username);
        return userRepository.findByUsername(encrypted)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.status(404).build());
    }

    public ResponseEntity<?> setUserEnabledStatus(Long id, boolean status) {
        return userRepository.findById(id).map(user -> {
            user.setEnabled(status);
            userRepository.save(user);
            return ResponseEntity.ok(Map.of("message", status ? "User enabled" : "User disabled"));
        }).orElse(ResponseEntity.status(404).body(Map.of("error", "User not found")));
    }

    public ResponseEntity<?> changeUserRole(String rawUsername, String newRole) {
        String encryptedUsername = encryptService.encrypt(rawUsername);
        var user = userRepository.findByUsername(encryptedUsername)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Role role = roleRepository.findByName(newRole.toUpperCase())
                .orElseThrow(() -> new RuntimeException("Role not found"));

        user.setRole(role);
        userRepository.save(user);
        return ResponseEntity.ok(Map.of("message", "Role updated successfully"));
    }

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    public String encryptUsername(String rawUsername) {
        return encryptService.encrypt(rawUsername);
    }

    public String decryptUsername(String encrypted) {
        return encryptService.decrypt(encrypted);
    }
}
