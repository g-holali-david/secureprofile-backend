# Base image
FROM eclipse-temurin:17-jdk-alpine

# Add non-root user
RUN addgroup -S secureprofile && adduser -S secureprofile -G appgroup

WORKDIR /app

COPY .env .env

# Copy project files
COPY target/secureprofile-backend-*.jar app.jar

# Change ownership
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER secureprofile

# Run application
ENTRYPOINT ["java", "-jar", "app.jar"]
