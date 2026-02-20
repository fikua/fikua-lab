dependencies {
    implementation(project(":fikua-core"))

    // HTTP server
    implementation("io.javalin:javalin:${property("javalinVersion")}")

    // Database
    implementation("org.postgresql:postgresql:${property("postgresqlVersion")}")
    implementation("com.zaxxer:HikariCP:${property("hikariVersion")}")

    // JSON
    implementation("com.fasterxml.jackson.core:jackson-databind:${property("jacksonVersion")}")

    // Nimbus JOSE (needed for ECKey references)
    implementation("com.nimbusds:nimbus-jose-jwt:${property("nimbusVersion")}")

    // PEM file loading
    implementation("org.bouncycastle:bcpkix-jdk18on:${property("bouncyCastleVersion")}")

    // Logging
    implementation("org.slf4j:slf4j-api:${property("slf4jVersion")}")
    implementation("ch.qos.logback:logback-classic:${property("logbackVersion")}")
}
