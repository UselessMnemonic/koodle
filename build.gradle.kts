import org.gradle.api.tasks.testing.Test
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("multiplatform") version "2.4.21"
}

group = "com.uselessmnemonic"
version = "0.1.0-SNAPSHOT"

kotlin {
    explicitApi()

    jvm {
        compilerOptions.jvmTarget.set(JvmTarget.JVM_17)
    }
    linuxArm64()
    macosArm64 {
        binaries.executable("decoderChecks") {
            compilation = compilations.getByName("test")
            entryPoint = "com.uselessmnemonic.koodle.main"
        }
    }

    // The default hierarchy shares nativeMain between both ARM64 targets.
    // Only the Kotlin standard library is needed; no third-party dependencies.
}

val jvmChecks = tasks.register<JavaExec>("decoderChecks") {
    group = "verification"
    description = "Runs dependency-free decoder regression checks on JVM."
    val compilation = kotlin.targets.getByName("jvm").compilations.getByName("test")
    dependsOn(compilation.compileTaskProvider)
    classpath(compilation.output.allOutputs, compilation.runtimeDependencyFiles)
    mainClass.set("com.uselessmnemonic.koodle.DecoderChecksKt")
}

// Checks are dependency-free executable tests rather than JUnit tests.
tasks.named<Test>("jvmTest") { enabled = false }
tasks.named("check") { dependsOn(jvmChecks) }
