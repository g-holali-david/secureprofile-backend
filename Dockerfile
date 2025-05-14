# Base image
FROM eclipse-temurin:17-jdk-alpine

# Add non-root user
RUN addgroup -S secureprofile && adduser -S secureprofile -G secureprofile

# Declare workdir
WORKDIR /app

# Define build-time arguments (from GitHub Actions)
ARG DB_HOST
ARG DB_PORT
ARG DB_NAME
ARG DB_USER
ARG DB_PASS
ARG JWT_SECRET
ARG JWT_ACCESS_EXPIRATION_MS
ARG JWT_REFRESH_EXPIRATION_MS
ARG ENC_ALGORITHM
ARG ENC_SECRET_KEY

# Set environment variables for the app (optional but good for debugging)
ENV DB_HOST=$DB_HOST \
    DB_PORT=$DB_PORT \
    DB_NAME=$DB_NAME \
    DB_USER=$DB_USER \
    DB_PASS=$DB_PASS \
    JWT_SECRET=$JWT_SECRET \
    JWT_ACCESS_EXPIRATION_MS=$JWT_ACCESS_EXPIRATION_MS \
    JWT_REFRESH_EXPIRATION_MS=$JWT_REFRESH_EXPIRATION_MS \
    ENC_ALGORITHM=$ENC_ALGORITHM \
    ENC_SECRET_KEY=$ENC_SECRET_KEY

# Copy jar
COPY target/backend-0.0.1-SNAPSHOT.jar app.jar

# Permissions
RUN chown -R secureprofile:secureprofile /app

# Use non-root user
USER secureprofile

# Launch application
ENTRYPOINT ["java", "-jar", "app.jar"]
