# Multi-stage build for Fikua Lab
FROM eclipse-temurin:25-jdk AS builder

WORKDIR /build
COPY suite/backend/ .
RUN chmod +x gradlew \
    && ./gradlew :fikua-lab:fatJar --no-daemon

FROM eclipse-temurin:25-jre

# Install curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN addgroup --gid 1001 fikua && adduser --uid 1001 --gid 1001 --disabled-password --gecos "" fikua

WORKDIR /app

# Copy fat jar and migrations
COPY --from=builder /build/fikua-lab/build/libs/fikua-lab-*-all.jar app.jar
COPY --from=builder /build/fikua-lab/src/main/resources/db/migration/ /app/migrations/

# Certs directory (mounted at runtime)
RUN mkdir -p /app/certs && chown -R fikua:fikua /app

USER fikua

EXPOSE 8080

ENV FIKUA_PORT=8080
ENV FIKUA_CERTS_DIR=/app/certs

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["java", "-XX:+UseG1GC", "-XX:MaxRAMPercentage=75.0", "-jar", "app.jar"]
