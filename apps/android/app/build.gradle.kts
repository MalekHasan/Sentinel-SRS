// SPDX-License-Identifier: GPL-3.0-or-later
import javax.inject.Inject
import org.gradle.process.ExecOperations

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.compose.compiler)
}

val appMinSdk = 29 // Android 10: needed for ConnectivityManager.getConnectionOwnerUid
val rustAbis = listOf("arm64-v8a", "armeabi-v7a", "x86_64")

android {
    namespace = "io.github.malekhasan.sentinel"
    compileSdk = 37

    defaultConfig {
        applicationId = "io.github.malekhasan.sentinel"
        minSdk = appMinSdk
        targetSdk = 36
        versionCode = 1
        versionName = "0.0.1"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk { abiFilters += rustAbis }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
    }

    lint {
        abortOnError = true
        checkGeneratedSources = false
    }
}

dependencies {
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.material3)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.activity.compose)
    // The AAR variant of JNA carries libjnidispatch.so for each Android ABI.
    implementation(libs.jna) {
        artifact { type = "aar" }
    }

    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.junit)
}

// --- Rust core -------------------------------------------------------------------------
// The Rust workspace is two levels up. Two tasks feed the Android build:
//   cargoNdkBuild:   libsentinel_ffi.so for every ABI     -> jniLibs
//   uniffiBindings:  Kotlin bindings generated from the library -> Kotlin sources
// Needs `cargo`, `cargo-ndk` and ANDROID_NDK_HOME (see docs/ANDROID-BUILD.md).

val rustWorkspace: Directory = rootProject.layout.projectDirectory.dir("../..")

fun rustInputs() = rustWorkspace.asFileTree.matching {
    include("crates/**", "third_party/**", "Cargo.toml", "Cargo.lock", "rust-toolchain.toml")
    exclude("**/target/**", "**/lab/**")
}

abstract class CargoNdkBuild : DefaultTask() {
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val sources: ConfigurableFileCollection

    @get:Input
    abstract val abis: ListProperty<String>

    @get:Input
    abstract val platform: Property<Int>

    @get:Internal
    abstract val workspace: DirectoryProperty

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @get:Inject
    abstract val execOps: ExecOperations

    @TaskAction
    fun build() {
        val args = mutableListOf("cargo", "ndk", "--platform", platform.get().toString())
        abis.get().forEach { args += listOf("-t", it) }
        args += listOf("-o", outputDir.get().asFile.absolutePath)
        args += listOf("build", "--release", "--locked", "-p", "sentinel-ffi")
        execOps.exec {
            workingDir = workspace.get().asFile
            commandLine(args)
        }
    }
}

abstract class UniffiBindings : DefaultTask() {
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val sources: ConfigurableFileCollection

    @get:Internal
    abstract val workspace: DirectoryProperty

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @get:Inject
    abstract val execOps: ExecOperations

    @TaskAction
    fun generate() {
        val root = workspace.get().asFile
        // Bindings depend only on the library's exported API, so a host build is enough.
        execOps.exec {
            workingDir = root
            commandLine("cargo", "build", "--locked", "-p", "sentinel-ffi")
        }
        val os = System.getProperty("os.name").lowercase()
        val library = when {
            os.contains("mac") -> "libsentinel_ffi.dylib"
            os.contains("windows") -> "sentinel_ffi.dll"
            else -> "libsentinel_ffi.so"
        }
        execOps.exec {
            workingDir = root
            commandLine(
                "cargo", "run", "--locked", "-q", "-p", "sentinel-ffi", "--features", "cli",
                "--bin", "uniffi-bindgen", "--", "generate",
                "--library", root.resolve("target/debug/$library").absolutePath,
                "--language", "kotlin", "--no-format",
                "--out-dir", outputDir.get().asFile.absolutePath,
            )
        }
    }
}

val cargoNdkBuild = tasks.register<CargoNdkBuild>("cargoNdkBuild") {
    sources.from(rustInputs())
    abis.set(rustAbis)
    platform.set(appMinSdk)
    workspace.set(rustWorkspace)
}

val uniffiBindings = tasks.register<UniffiBindings>("uniffiBindings") {
    sources.from(rustInputs())
    workspace.set(rustWorkspace)
}

androidComponents {
    onVariants { variant ->
        variant.sources.jniLibs?.addGeneratedSourceDirectory(cargoNdkBuild, CargoNdkBuild::outputDir)
        variant.sources.kotlin?.addGeneratedSourceDirectory(uniffiBindings, UniffiBindings::outputDir)
    }
}
