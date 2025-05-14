package ms.secureprofile.backend.controller;

import jakarta.validation.Valid;
import ms.secureprofile.backend.model.RefreshToken;
import ms.secureprofile.backend.model.User;
import ms.secureprofile.backend.repository.UserRepository;
import ms.secureprofile.backend.security.JwtService;
import ms.secureprofile.backend.security.LoginAttemptService;
import ms.secureprofile.backend.service.RefreshTokenService;
import ms.secureprofile.backend.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Contrôleur d’authentification REST.
 * Gère les opérations de sécurité :
 * - Enregistrement (register)
 * - Connexion (login)
 * - Rafraîchissement de token (refresh)
 * - Déconnexion (logout)
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    // Services métiers injectés via le constructeur
    private final UserService userService;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService refreshTokenService;
    private final UserRepository userRepository;
    private final LoginAttemptService loginAttemptService;

    /**
     * Constructeur d'injection des dépendances nécessaires.
     */
    public AuthController(UserService userService,
                          JwtService jwtService,
                          AuthenticationManager authenticationManager,
                          RefreshTokenService refreshTokenService,
                          UserRepository userRepository,
                          LoginAttemptService loginAttemptService) {
        this.userService = userService;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.refreshTokenService = refreshTokenService;
        this.userRepository = userRepository;
        this.loginAttemptService = loginAttemptService;
    }

    /**
     * ✅ Enregistrement (Register) :
     * - Crée un nouvel utilisateur
     * - Chiffre le username et l’email
     * - Hash le mot de passe
     * - Attribue par défaut le rôle USER
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody @Valid User user) {
        User savedUser = userService.register(user);
        return ResponseEntity.ok(Map.of("message", "User registered successfully"));
    }

    /**
     * ✅ Connexion (Login) :
     * - Authentifie l’utilisateur via Spring Security
     * - Vérifie s’il est temporairement bloqué (anti-brute-force)
     * - Génère un accessToken (JWT) + refreshToken (stocké en BDD)
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> credentials) {
        String username = credentials.get("username");
        String password = credentials.get("password");

        // 🔐 Mécanisme anti-brute-force : bloque l’accès temporairement après trop d’échecs
        if (loginAttemptService.isBlocked(username)) {
            long seconds = loginAttemptService.remainingBlockSeconds(username);
            return ResponseEntity.status(403).body(Map.of(
                    "error", "Too many failed attempts. Try again in " + seconds + " seconds."
            ));
        }

        try {
            // 🔐 Authentifie l’utilisateur (utilise BCrypt et UserDetailsService en interne)
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );

            // ✅ Authentification réussie → on récupère les détails utilisateur
            UserDetails userDetails = (UserDetails) auth.getPrincipal();
            String accessToken = jwtService.generateAccessToken(userDetails.getUsername());

            // 🔍 On retrouve l’utilisateur (stocké avec username chiffré)
            User user = userRepository.findByUsername(userService.encryptUsername(username))
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // 🎟️ On génère un refresh token unique (stocké en base, durée plus longue)
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

            // 🔁 Réinitialise le compteur d’échecs après succès
            loginAttemptService.loginSucceeded(username);

            // ✅ Renvoie les deux tokens au frontend
            return ResponseEntity.ok(Map.of(
                    "accessToken", accessToken,
                    "refreshToken", refreshToken.getToken()
            ));

        } catch (AuthenticationException e) {
            //   Échec de connexion → incrémente le compteur d’échecs
            loginAttemptService.loginFailed(username);

            //   Message d’erreur générique pour éviter les fuites d’info
            return ResponseEntity.status(401).body(Map.of(
                    "error", "Invalid username or password"
            ));
        }
    }

    /**
     *   Rafraîchissement de token :
     * - Vérifie que le refresh token est valide et non expiré
     * - Renvoie un nouveau accessToken (sans re-saisir le mot de passe)
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> request) {
        String requestToken = request.get("refreshToken");

        // Vérifie que le token est en base et non expiré
        RefreshToken refreshToken = refreshTokenService.findByToken(requestToken)
                .map(refreshTokenService::verifyExpiration)
                .orElseThrow(() -> new RuntimeException("Refresh token not found or expired"));

        // Déchiffre le username (il est stocké chiffré dans l’entité User)
        String username = refreshToken.getUser().getUsername();
        String decryptedUsername = userService.decryptUsername(username);

        // énère un nouveau accessToken
        String newAccessToken = jwtService.generateAccessToken(decryptedUsername);

        return ResponseEntity.ok(Map.of("accessToken", newAccessToken));
    }

    /**
     *   Déconnexion (Logout) :
     * - Supprime tous les refresh tokens associés à l’utilisateur
     * - Ainsi, aucun nouveau accessToken ne peut être généré
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody Map<String, String> request) {
        String username = request.get("username");

        // Retrouve le User en base à partir du nom chiffré
        User user = userRepository.findByUsername(userService.encryptUsername(username))
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Supprime les tokens longs stockés (révocation)
        refreshTokenService.deleteByUser(user);

        return ResponseEntity.ok(Map.of("message", "User logged out. Refresh token deleted."));
    }
}
