package ms.secureprofile.backend.service;

import ms.secureprofile.backend.model.Role;
import ms.secureprofile.backend.model.User;
import ms.secureprofile.backend.repository.RoleRepository;
import ms.secureprofile.backend.repository.UserRepository;
import ms.secureprofile.backend.security.EncryptService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
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

    /**
     * Enregistre un nouvel utilisateur après validation.
     * - Ne modifie pas l'objet validé (important pour éviter des erreurs de validation)
     * - Chiffre le username et l'email
     * - Hash le mot de passe
     * - Attribue un rôle par défaut
     */
    public User register(User user) {

        // Vérifie que l’email est bien formé AVANT de le chiffrer
        if (!isValidEmail(user.getEmail())) {
            throw new RuntimeException("Email format is invalid");
        }

        // Vérifie que l'email chiffré n'existe pas déjà
        if (userRepository.existsByEmail(encryptService.encrypt(user.getEmail()))) {
            throw new RuntimeException("Email already in use");
        }

        // Vérifie que le username chiffré n'existe pas déjà
        if (userRepository.existsByUsername(encryptService.encrypt(user.getUsername()))) {
            throw new RuntimeException("Username already in use");
        }

        // ⚠️ NE PAS modifier l'objet validé pour éviter que Hibernate valide des champs invalides
        // Crée un nouvel objet User avec les valeurs sécurisées
        User securedUser = new User();

        securedUser.setUsername(encryptService.encrypt(user.getUsername()));
        securedUser.setEmail(encryptService.encrypt(user.getEmail()));
        securedUser.setPassword(passwordEncoder.encode(user.getPassword()));
        securedUser.setFirstName(user.getFirstName());
        securedUser.setLastName(user.getLastName());
        securedUser.setEnabled(true);
        securedUser.setCreatedAt(LocalDateTime.now());
        securedUser.setUpdatedAt(LocalDateTime.now());

        // Affecte le rôle par défaut (USER)
        securedUser.setRole(roleRepository.findByName("USER")
                .orElseThrow(() -> new RuntimeException("Default role USER not found")));

        // Enregistre en base
        return userRepository.save(securedUser);
    }

    /**
     * Récupère un utilisateur par username (en version chiffrée)
     */

    public User getByUsername(String rawUsername) {
        String encrypted = encryptService.encrypt(rawUsername);
        User user = userRepository.findByUsername(encrypted)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Créer un objet User "clone" pour exposer les données déchiffrées
        User visibleUser = new User();
        visibleUser.setFirstName(user.getFirstName());
        visibleUser.setLastName(user.getLastName());
        visibleUser.setUsername(encryptService.decrypt(user.getUsername())); // déchiffrement ici
        visibleUser.setEmail(encryptService.decrypt(user.getEmail()));       // déchiffrement ici
        visibleUser.setRole(user.getRole());
        visibleUser.setCreatedAt(user.getCreatedAt());
        visibleUser.setUpdatedAt(user.getUpdatedAt());
        visibleUser.setEnabled(user.isEnabled());

        return visibleUser;
    }

    /**
     * Met à jour les informations de profil (prénom / nom) d'un utilisateur.
     */
    public void updateUserProfile(String rawUsername, Map<String, String> updates) {
        User user = getByUsername(rawUsername);
        if (updates.containsKey("firstName")) user.setFirstName(updates.get("firstName"));
        if (updates.containsKey("lastName")) user.setLastName(updates.get("lastName"));
        user.setUpdatedAt(LocalDateTime.now());
        userRepository.save(user);
    }

    /**
     * Change le mot de passe d’un utilisateur si l’ancien est correct.
     */
    public void changePassword(String rawUsername, String oldPwd, String newPwd) {
        User user = getByUsername(rawUsername);
        if (!passwordEncoder.matches(oldPwd, user.getPassword())) {
            throw new RuntimeException("Incorrect current password");
        }
        user.setPassword(passwordEncoder.encode(newPwd));
        user.setUpdatedAt(LocalDateTime.now());
        userRepository.save(user);
    }

    /**
     * Supprime un utilisateur à partir du username brut.
     */
    public void deleteByUsername(String rawUsername) {
        User user = getByUsername(rawUsername);
        userRepository.delete(user);
    }

    /**
     * Supprime un utilisateur à partir de son ID.
     */
    public ResponseEntity<?> deleteById(Long id) {
        if (!userRepository.existsById(id)) return ResponseEntity.notFound().build();
        userRepository.deleteById(id);
        return ResponseEntity.ok(Map.of("message", "User deleted"));
    }

    /**
     * Recherche un utilisateur par username (renvoie une réponse HTTP).
     */
    public ResponseEntity<User> searchByUsername(String username) {
        String encrypted = encryptService.encrypt(username);
        return userRepository.findByUsername(encrypted)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.status(404).build());
    }

    /**
     * Active ou désactive un utilisateur à partir de son ID.
     */
    public ResponseEntity<?> setUserEnabledStatus(Long id, boolean status) {
        return userRepository.findById(id).map(user -> {
            user.setEnabled(status);
            user.setUpdatedAt(LocalDateTime.now());
            userRepository.save(user);
            return ResponseEntity.ok(Map.of("message", status ? "User enabled" : "User disabled"));
        }).orElse(ResponseEntity.status(404).body(Map.of("error", "User not found")));
    }

    /**
     * Change le rôle d’un utilisateur.
     */
    public ResponseEntity<?> changeUserRole(String rawUsername, String newRole) {
        String encryptedUsername = encryptService.encrypt(rawUsername);
        var user = userRepository.findByUsername(encryptedUsername)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Role role = roleRepository.findByName(newRole.toUpperCase())
                .orElseThrow(() -> new RuntimeException("Role not found"));

        user.setRole(role);
        user.setUpdatedAt(LocalDateTime.now());
        userRepository.save(user);
        return ResponseEntity.ok(Map.of("message", "Role updated successfully"));
    }

    /**
     * Récupère tous les utilisateurs (admin uniquement).
     */
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    /**
     * Utilitaire : chiffre un username brut.
     */
    public String encryptUsername(String rawUsername) {
        return encryptService.encrypt(rawUsername);
    }

    /**
     * Utilitaire : déchiffre un username chiffré.
     */
    public String decryptUsername(String encrypted) {
        return encryptService.decrypt(encrypted);
    }

    private boolean isValidEmail(String email) {
        return email != null && email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$");
    }
}
