dependencies {
    implementation(project(":fikua-core"))

    // HTTP server
    implementation("io.javalin:javalin:${property("javalinVersion")}")

    // JSON
    implementation("com.fasterxml.jackson.core:jackson-databind:${property("jacksonVersion")}")

    // Nimbus JOSE (WIA signing) + BouncyCastle (PEM key loading)
    implementation("com.nimbusds:nimbus-jose-jwt:${property("nimbusVersion")}")
    implementation("org.bouncycastle:bcpkix-jdk18on:${property("bouncyCastleVersion")}")

    // Logging
    implementation("org.slf4j:slf4j-api:${property("slf4jVersion")}")
    implementation("ch.qos.logback:logback-classic:${property("logbackVersion")}")
}
