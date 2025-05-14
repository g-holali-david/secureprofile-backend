package ms.secureprofile.backend.security;

import ms.secureprofile.backend.model.User;
import ms.secureprofile.backend.repository.UserRepository;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;

import java.util.Collections;

/**
 * Implémentation personnalisée de UserDetailsService,
 * utilisée par Spring Security pour charger un utilisateur à partir de son username.
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;
    private final EncryptService encryptService;

    public UserDetailsServiceImpl(UserRepository userRepository, EncryptService encryptService) {
        this.userRepository = userRepository;
        this.encryptService = encryptService;
    }

    /**
     * Charge l'utilisateur chiffré à partir du username en base.
     * Le username envoyé dans le token JWT est déjà en clair, donc on le chiffre
     * pour pouvoir faire la comparaison avec la BDD.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        String encryptedUsername = encryptService.encrypt(username);

        User user = userRepository.findByUsername(encryptedUsername)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return new org.springframework.security.core.userdetails.User(
                username, // username original (déchiffré déjà via JWT)
                user.getPassword(), // mot de passe haché
                Collections.singleton(() -> "ROLE_" + user.getRole().getName()) // rôle Spring Security
        );
    }
}
