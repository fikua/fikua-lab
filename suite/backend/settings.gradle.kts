plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

rootProject.name = "fikua-lab"

include("fikua-core")
include("fikua-issuer")
include("fikua-verifier")
include("fikua-trustlist")
include("fikua-lab")
