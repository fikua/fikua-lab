plugins {
    application
}

application {
    mainClass.set("com.fikua.server.FikuaLab")
    applicationDefaultJvmArgs = emptyList()
}

dependencies {
    implementation(project(":fikua-core"))

    // HTTP server
    implementation("io.javalin:javalin:${property("javalinVersion")}")

    // Database
    implementation("org.postgresql:postgresql:${property("postgresqlVersion")}")
    implementation("com.zaxxer:HikariCP:${property("hikariVersion")}")
    implementation("org.flywaydb:flyway-core:${property("flywayVersion")}")
    implementation("org.flywaydb:flyway-database-postgresql:${property("flywayVersion")}")

    // YAML config loading
    implementation("org.yaml:snakeyaml:${property("snakeyamlVersion")}")

    // JSON (transitive from core, but explicit for server-specific use)
    implementation("com.fasterxml.jackson.core:jackson-databind:${property("jacksonVersion")}")

    // Nimbus JOSE (needed for ECKey references in server code)
    implementation("com.nimbusds:nimbus-jose-jwt:${property("nimbusVersion")}")

    // Logging
    implementation("org.slf4j:slf4j-api:${property("slf4jVersion")}")
    implementation("ch.qos.logback:logback-classic:${property("logbackVersion")}")
}

tasks.named<Jar>("jar") {
    manifest {
        attributes["Main-Class"] = "com.fikua.server.FikuaLab"
    }
}

tasks.register<Jar>("fatJar") {
    archiveClassifier.set("all")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    manifest {
        attributes["Main-Class"] = "com.fikua.server.FikuaLab"
    }
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
    with(tasks.jar.get())
}
