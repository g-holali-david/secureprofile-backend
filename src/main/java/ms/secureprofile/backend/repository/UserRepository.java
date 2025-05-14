package ms.secureprofile.backend.repository;

import ms.secureprofile.backend.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * Repository Spring Data pour l'entité User.
 * Fournit des méthodes CRUD, ainsi qu'une méthode personnalisée de recherche par username (chiffré).
 */
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    boolean existsByEmail(String email);
    boolean existsByUsername(String username);

}
