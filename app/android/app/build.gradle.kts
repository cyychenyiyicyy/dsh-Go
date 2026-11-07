import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.util.Properties

plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

val keyProps = Properties().apply {
    rootProject.file("key.properties").takeIf { it.exists() }?.inputStream()?.use { load(it) }
}

// Debug builds use the release key only when it is all there; they are never the build
// that should stop over a half-filled key.properties.
// A password may be nothing but spaces; a path or an alias may not.
val hasWholeReleaseKey = listOf("storeFile", "keyAlias").all { !keyProps.getProperty(it).isNullOrBlank() } &&
    listOf("storePassword", "keyPassword").all { !keyProps.getProperty(it).isNullOrEmpty() } &&
    file(keyProps.getProperty("storeFile")).exists()

// Per-ABI runtime bundles produced by runtime/build-runtime.sh.
val runtimeOut = rootProject.file("../../runtime/out")

// versionCode is the build minute, same encoding as tooling/build_number.py:
// (year - 2026) * 10^8 + MMDDhhmm at UTC+8. tooling/build-apk.sh passes it as
// --build-number; this covers builds that skip the script (flutter run, the
// IDE), where pubspec's `+1` placeholder would be a downgrade and make
// `flutter run` uninstall the installed app, data included.
fun buildMinuteVersionCode(): Int {
    val t = OffsetDateTime.now(ZoneOffset.ofHours(8))
    return (t.year - 2026) * 100_000_000 + t.monthValue * 1_000_000 + t.dayOfMonth * 10_000 + t.hour * 100 + t.minute
}

android {
    namespace = "io.github.ccch1mneyyy.dsh_app"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        // Same code, separate install slot: lets the patched build live next to the
        // release-signed app instead of needing an uninstall (signatures differ).
        applicationId = "io.github.ccch1mneyyy.dsh_app.fix"
        // java.nio.file (symlinks while unpacking the rootfs) needs API 26.
        minSdk = 26
        // Target 28 like Termux, so the API 29+ exec restriction on app-private
        // files does not apply to binaries inside the rootfs.
        targetSdk = 28
        versionCode = flutter.versionCode.takeIf { it > 1 } ?: buildMinuteVersionCode()
        versionName = flutter.versionName
    }

    flavorDimensions += "abi"
    productFlavors {
        create("arm64") {
            dimension = "abi"
            ndk { abiFilters += "arm64-v8a" }
        }
        create("x64") {
            dimension = "abi"
            ndk { abiFilters += "x86_64" }
        }
    }

    sourceSets {
        getByName("arm64") {
            assets.srcDir(File(runtimeOut, "arm64-v8a/assets"))
            jniLibs.srcDir(File(runtimeOut, "arm64-v8a/jniLibs"))
        }
        getByName("x64") {
            assets.srcDir(File(runtimeOut, "x86_64/assets"))
            jniLibs.srcDir(File(runtimeOut, "x86_64/jniLibs"))
        }
    }

    packaging {
        // proot and friends ship as lib*.so; they must be extracted to
        // nativeLibraryDir so they can be executed.
        jniLibs {
            useLegacyPackaging = true
            // Keep the Termux binaries byte-identical to runtime/out (their hashes are in the manifest).
            keepDebugSymbols += listOf("**/libproot.so", "**/libproot-loader.so", "**/libtalloc.so", "**/libandroid-shmem.so")
        }
    }

    lint {
        // targetSdk 28 is deliberate (see docs/architecture.md); not a Play build.
        disable += "ExpiredTargetSdkVersion"
    }

    androidResources {
        noCompress += listOf("gz", "xz", "zst", "tar")
    }

    signingConfigs {
        if (!keyProps.isEmpty) {
            create("release") {
                storeFile = keyProps.getProperty("storeFile")?.let { file(it) }
                storePassword = keyProps.getProperty("storePassword")
                keyAlias = keyProps.getProperty("keyAlias")
                keyPassword = keyProps.getProperty("keyPassword")
                // All three schemes: AGP drops v1 for minSdk 24+, but some installers and
                // security scanners on Chinese ROMs still read the JAR signature.
                enableV1Signing = true
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        debug {
            // tooling/dev-run.sh installs debug over the release build on a phone, data
            // kept: Android only allows that with the same key.
            if (hasWholeReleaseKey) signingConfig = signingConfigs.getByName("release")
        }
        release {
            // Use the release key when configured; local builds without key.properties fall back to debug.
            signingConfig = signingConfigs.getByName(if (keyProps.isEmpty) "debug" else "release")
            // Ours on top of Flutter's: phone control's privileged process and
            // its TLS libraries are reached by class name (see the file).
            proguardFiles("proguard-rules.pro")
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

flutter {
    source = "../.."
}

dependencies {
    testImplementation("junit:junit:4.13.2")

    // .tar.xz support for the rootfs bundle.
    implementation("org.tukaani:xz:1.10")

    // 不打扰模式 (phone/background): a shell-uid privileged display via Shizuku or self-ADB.
    implementation("dev.rikka.shizuku:api:13.1.5")       // MIT
    implementation("dev.rikka.shizuku:provider:13.1.5")  // MIT
    implementation("com.github.MuntashirAkon:libadb-android:3.1.1") // used under its Apache-2.0 option; pulls in spake2-android (LGPL-3.0)
    implementation("org.conscrypt:conscrypt-android:2.8.0")         // Apache-2.0: libadb TLS/pairing
    // MIT: self-signed adb client cert. The same jdk15to18 family libadb-android
    // pulls in (bcprov-jdk15to18:1.81); adding jdk18on next to it duplicates every class.
    implementation("org.bouncycastle:bcpkix-jdk15to18:1.81")
    implementation("androidx.webkit:webkit:1.15.0") // Apache-2.0: web islands' force dark (webview_flutter's own version)
}
