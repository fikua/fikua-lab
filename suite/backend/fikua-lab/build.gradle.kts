plugins {
    application
}

application {
    mainClass.set("com.fikua.lab.FikuaLab")
    applicationDefaultJvmArgs = emptyList()
}

dependencies {
    implementation(project(":fikua-core"))
    implementation(project(":fikua-issuer"))

    // HTTP server
    implementation("io.javalin:javalin:${property("javalinVersion")}")

    // Database
    implementation("org.postgresql:postgresql:${property("postgresqlVersion")}")
    implementation("com.zaxxer:HikariCP:${property("hikariVersion")}")

    // YAML config loading
    implementation("org.yaml:snakeyaml:${property("snakeyamlVersion")}")

    // JSON
    implementation("com.fasterxml.jackson.core:jackson-databind:${property("jacksonVersion")}")

    // Logging
    implementation("org.slf4j:slf4j-api:${property("slf4jVersion")}")
    implementation("ch.qos.logback:logback-classic:${property("logbackVersion")}")
}

tasks.named<Jar>("jar") {
    manifest {
        attributes["Main-Class"] = "com.fikua.lab.FikuaLab"
    }
}

tasks.register<Jar>("fatJar") {
    archiveClassifier.set("all")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    manifest {
        attributes["Main-Class"] = "com.fikua.lab.FikuaLab"
    }
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) }) {
        exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA")
    }
    with(tasks.jar.get())
}
