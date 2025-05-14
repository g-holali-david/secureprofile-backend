package ms.secureprofile.backend.controller;

import ms.secureprofile.backend.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/users")
@PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/me")
    public ResponseEntity<?> getProfile(Authentication auth) {
        return ResponseEntity.ok(userService.getByUsername(auth.getName()));
    }

    @PutMapping("/me")
    public ResponseEntity<?> updateProfile(@RequestBody Map<String, String> updates, Authentication auth) {
        userService.updateUserProfile(auth.getName(), updates);
        return ResponseEntity.ok(Map.of("message", "Profile updated"));
    }

    @PatchMapping("/password")
    public ResponseEntity<?> changePassword(@RequestBody Map<String, String> body, Authentication auth) {
        String oldPwd = body.get("oldPassword");
        String newPwd = body.get("newPassword");
        userService.changePassword(auth.getName(), oldPwd, newPwd);
        return ResponseEntity.ok(Map.of("message", "Password updated"));
    }

    @DeleteMapping("/me")
    public ResponseEntity<?> deleteMyAccount(Authentication auth) {
        userService.deleteByUsername(auth.getName());
        return ResponseEntity.ok(Map.of("message", "Account deleted"));
    }
}
