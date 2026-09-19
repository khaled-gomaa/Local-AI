plugins {
    java
}

group = "localrecon"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation("net.portswigger.burp.extensions:montoya-api:2026.7")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

tasks.jar {
    archiveFileName.set("burp-recon-ai.jar")
    manifest {
        attributes["Main-Class"] = "localrecon.Extension"
    }
}
