# secureprofile-backend

## Auteur : GAVI Holali David

## Objectif du projet

Cette application backend est conçue pour gérer de manière sécurisée les utilisateurs (inscription, authentification, gestion des rôles, etc.) en mettant en œuvre plusieurs mécanismes de sécurité conformes aux bonnes pratiques.

## Technologies utilisées

- **Spring Boot**
- **Spring Security**
- **JWT (JSON Web Tokens)**
- **PostgreSQL** via Render
- **Validation Bean & Hibernate Validator**
- **Encryption AES & Hashing (BCrypt)**
- **Docker**
- **Spring Scheduler**
- **GitHub Actions (CI/CD)**

---

## Structure du projet

Le code est organisé en plusieurs packages :

- `controller` : Contient les endpoints REST (`AuthController`, `UserController`, `AdminController`)
- `model` : Entités JPA (`User`, `Role`, `RefreshToken`, `BlacklistToken`, etc.)
- `repository` : Interfaces Spring Data JPA
- `security` : Logique de sécurité, JWT, encryption et filtres
- `validation` : Contraintes personnalisées (mot de passe fort)
- `jobs` : Tâches planifiées (cron) comme le nettoyage automatique des tokens expirés
- `exception` : Gestion centralisée des erreurs (par exemple : validations)

---

## Mécanismes de sécurité mis en place

### 🔐 Authentification sécurisée

- Basée sur `JWT` avec expiration courte pour les tokens d’accès.
- Utilisation de **Refresh Tokens** stockés en base pour renouveler un JWT expiré.
- Stockage en base du refresh token avec date d’expiration.

### 🔒 Hachage et chiffrement

- **Mot de passe** : haché avec `BCrypt`
- **Username / Email** : chiffrés avec `AES` (utilisation d’un secret dans le `.env`)

### 🚫 Protection contre les attaques

- **Token blacklist** : les refresh tokens invalidés (logout) sont stockés et non acceptés s’ils sont réutilisés.
- **Brute-force** : gestion des tentatives de connexion, blocage temporaire (compteur en mémoire)

### 🛡️ Validation avancée

- Validation des champs avec `@Valid`
- Email vérifié par `@Email`
- Mot de passe validé par annotation personnalisée `@StrongPassword(min = 12)`

### 👮 Rôles et autorisations

- Utilisation de `@PreAuthorize` pour sécuriser les routes (USER, ADMIN)
- Possibilité de changer le rôle via l’interface admin (`/admin/change-role`)

### 🧹 Nettoyage automatique

- Tâche planifiée (`TokenCleanupJob`) qui supprime les refresh tokens expirés.

### 📜 Audit

- Log de certaines actions sensibles (connexion, logout) dans une entité `AuditLog`.

---

## Endpoints clés

| Méthode | URL                         | Description                              |
|--------|-----------------------------|------------------------------------------|
| POST   | `/auth/register`            | Inscription avec rôle `USER` par défaut  |
| POST   | `/auth/login`               | Authentification et retour des tokens    |
| POST   | `/auth/refresh`             | Génère un nouveau token d’accès          |
| POST   | `/auth/logout`              | Invalide le refresh token                |
| GET    | `/users/me`                 | Récupère les infos du profil             |
| PATCH  | `/users/password`           | Modifier son mot de passe                |
| DELETE | `/users/me`                 | Supprimer son compte                     |
| GET    | `/admin/users`              | Voir tous les utilisateurs               |
| PATCH  | `/admin/users/{id}/enable`  | Activer un compte                        |
| PATCH  | `/admin/users/{id}/disable` | Désactiver un compte                     |
| POST   | `/admin/change-role`        | Modifier le rôle d’un utilisateur        |

---

## Conteneurisation

Le projet inclut un `Dockerfile` permettant de construire une image exécutable.
> Les variables sensibles sont chargées via un fichier `.env` externe au conteneur.

---

## CI / CD

Le projet inclut un pipeline GitHub Actions (`.github/workflows/ci.yml`) avec :

- Compilation du backend
- Lint et vérifications de sécurité
- Préparation à l’intégration continue

---

## Remarques

- Le projet est conçu pour séparer clairement **la sécurité** dans un package dédié.
- Le choix de chiffrer les usernames/emails avant stockage permet d'assurer la **confidentialité** même en cas d'accès à la base.
- Toutes les routes critiques sont protégées par `@PreAuthorize` avec vérification des rôles.
- Des annotations personnalisées permettent d’avoir une **validation forte et réutilisable** des mots de passe.

---

## Auteur

Projet réalisé dans le cadre du **TP d’Intégration et Sécurisation des bases de données** – Mastère IPSSI.
