dependencies {
    // JWT, JWS, JWE, JWK operations
    implementation("com.nimbusds:nimbus-jose-jwt:${property("nimbusVersion")}")

    // JSON serialization
    implementation("com.fasterxml.jackson.core:jackson-databind:${property("jacksonVersion")}")
    implementation("com.fasterxml.jackson.datatype:jackson-datatype-jsr310:${property("jacksonVersion")}")

    // Logging API only (no implementation in core)
    implementation("org.slf4j:slf4j-api:${property("slf4jVersion")}")
}
