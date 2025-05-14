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

ENV DB_HOST=$DB_HOST
ENV DB_PORT=$DB_PORT
ENV DB_NAME=$DB_NAME
ENV DB_USER=$DB_USER
ENV DB_PASS=$DB_PASS
ENV JWT_SECRET=$JWT_SECRET
ENV JWT_ACCESS_EXPIRATION_MS=$JWT_ACCESS_EXPIRATION_MS
ENV JWT_REFRESH_EXPIRATION_MS=$JWT_REFRESH_EXPIRATION_MS
ENV ENC_ALGORITHM=$ENC_ALGORITHM
ENV ENC_SECRET_KEY=$ENC_SECRET_KEY

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
