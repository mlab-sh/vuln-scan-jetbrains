import org.jetbrains.intellij.platform.gradle.TestFrameworkType

plugins {
    id("org.jetbrains.kotlin.jvm") version "2.2.21"
    id("org.jetbrains.intellij.platform") version "2.19.0"
}

group = "sh.mlab"
version = providers.gradleProperty("pluginVersion").get()

kotlin {
    jvmToolchain(21)
    compilerOptions {
        // Stay on the stdlib API the oldest supported IDE (243) ships.
        apiVersion = org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_0
        languageVersion = org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_0
        // Real JVM default methods: without this, Kotlin emits bridges to the
        // platform interfaces' defaults, which the verifier flags as internal API.
        jvmDefault = org.jetbrains.kotlin.gradle.dsl.JvmDefaultMode.NO_COMPATIBILITY
    }
}

repositories {
    mavenCentral()
    intellijPlatform { defaultRepositories() }
}

dependencies {
    intellijPlatform {
        intellijIdeaCommunity(providers.gradleProperty("platformVersion"))
        testFramework(TestFrameworkType.Platform)
    }
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.opentest4j:opentest4j:1.3.0")
}

intellijPlatform {
    pluginConfiguration {
        version = providers.gradleProperty("pluginVersion")
        ideaVersion {
            sinceBuild = providers.gradleProperty("pluginSinceBuild")
            // Open ended on purpose: no until-build, as Marketplace recommends.
            untilBuild = provider { null }
        }
    }
    pluginVerification {
        // The IDE set Marketplace itself checks against, from sinceBuild on.
        ides {
            // `-PverifyIdes=IC-2024.3.6,IU-2026.2.3` checks a subset locally;
            // CI runs the full recommended set.
            val only = providers.gradleProperty("verifyIdes").orNull
            if (only == null) recommended()
            else only.split(',').forEach { n ->
                val (type, v) = n.trim().split('-', limit = 2)
                create(org.jetbrains.intellij.platform.gradle.IntelliJPlatformType.fromCode(type), v)
            }
        }
    }
    signing {
        certificateChain = providers.environmentVariable("CERTIFICATE_CHAIN")
        privateKey = providers.environmentVariable("PRIVATE_KEY")
        password = providers.environmentVariable("PRIVATE_KEY_PASSWORD")
    }
    publishing {
        token = providers.environmentVariable("PUBLISH_TOKEN")
    }
}

tasks.test {
    // Fixtures are shared verbatim with the VS Code extension.
    systemProperty("mlab.fixtures", layout.projectDirectory.dir("src/test/fixtures").asFile.absolutePath)
}
