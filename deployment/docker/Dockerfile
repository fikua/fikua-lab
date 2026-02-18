# Multi-stage build for Fikua Lab
FROM eclipse-temurin:25-jdk AS builder

WORKDIR /build
COPY suite/backend/ .
RUN chmod +x gradlew && ./gradlew :fikua-server:fatJar --no-daemon

FROM eclipse-temurin:25-jre

# Non-root user
RUN groupadd -g 1000 fikua && useradd -u 1000 -g fikua -s /bin/bash fikua

WORKDIR /app

# Copy fat jar
COPY --from=builder /build/fikua-server/build/libs/fikua-server-*-all.jar app.jar

# Certs directory (mounted at runtime)
RUN mkdir -p /app/certs && chown -R fikua:fikua /app

USER fikua

EXPOSE 8080

ENV FIKUA_PORT=8080
ENV FIKUA_CERTS_DIR=/app/certs

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["java", "-XX:+UseG1GC", "-XX:MaxRAMPercentage=75.0", "-jar", "app.jar"]
