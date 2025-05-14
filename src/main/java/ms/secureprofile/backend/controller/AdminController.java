package ms.secureprofile.backend.controller;

import ms.secureprofile.backend.model.User;
import ms.secureprofile.backend.repository.RoleRepository;
import ms.secureprofile.backend.repository.UserRepository;
import ms.secureprofile.backend.security.EncryptService;
import ms.secureprofile.backend.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final EncryptService encryptService;
    private final UserService userService;

    public AdminController(UserRepository userRepository,
                           RoleRepository roleRepository,
                           EncryptService encryptService,
                           UserService userService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.encryptService = encryptService;
        this.userService = userService;
    }

    @PostMapping("/change-role")
    public ResponseEntity<?> changeUserRole(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String newRole = request.get("role");

        String encryptedUsername = encryptService.encrypt(username);

        var user = userRepository.findByUsername(encryptedUsername)
                .orElseThrow(() -> new RuntimeException("User not found"));

        var role = roleRepository.findByName(newRole.toUpperCase())
                .orElseThrow(() -> new RuntimeException("Role not found"));

        user.setRole(role);
        userRepository.save(user);

        return ResponseEntity.ok(Map.of("message", "Role updated successfully"));
    }

    @GetMapping("/users")
    public ResponseEntity<List<User>> listAllUsers() {
        return ResponseEntity.ok(userRepository.findAll());
    }

    @DeleteMapping("/users/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        if (!userRepository.existsById(id)) {
            return ResponseEntity.notFound().build();
        }
        userRepository.deleteById(id);
        return ResponseEntity.ok(Map.of("message", "User deleted"));
    }

    @GetMapping("/users/search")
    public ResponseEntity<?> searchUser(@RequestParam String username) {
        String encryptedUsername = encryptService.encrypt(username);
        return userRepository.findByUsername(encryptedUsername)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.status(404).build());
    }

    @PatchMapping("/users/{id}/enable")
    public ResponseEntity<?> enableUser(@PathVariable Long id) {
        return userService.setUserEnabledStatus(id, true);
    }

    @PatchMapping("/users/{id}/disable")
    public ResponseEntity<?> disableUser(@PathVariable Long id) {
        return userService.setUserEnabledStatus(id, false);
    }
}
