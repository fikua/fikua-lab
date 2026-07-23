plugins {
    java
    id("org.sonarqube") version "7.3.1.8318"
}

sonar {
    properties {
        property("sonar.projectKey", "fikua_fikua-lab")
        property("sonar.organization", "fikua")
        property("sonar.host.url", "https://sonarcloud.io")
    }
}

allprojects {
    group = property("group") as String
    version = "0.8.0"

    repositories {
        mavenCentral()
    }
}

subprojects {
    apply(plugin = "java")

    java {
        toolchain {
            languageVersion.set(JavaLanguageVersion.of(25))
        }
    }

    tasks.withType<JavaCompile> {
        options.encoding = "UTF-8"
    }

    tasks.withType<Test> {
        useJUnitPlatform()
    }

    dependencies {
        testImplementation("org.junit.jupiter:junit-jupiter:${property("junitVersion")}")
        testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    }
}
