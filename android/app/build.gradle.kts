import java.util.Properties

plugins {
    id("com.android.application")
}

// The single source of truth for which console this build opens. See gradle.properties.
val consoleHost: String = providers.gradleProperty("deskrally.consoleHost").get().trim()
require(Regex("^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$").matches(consoleHost)) {
    "deskrally.consoleHost must be a bare hostname (no scheme, port or path): $consoleHost"
}

// keystore.properties is gitignored and sits next to settings.gradle.kts. Without it the release
// build is simply unsigned, which is what a fresh checkout should get.
val keystoreProps = Properties().apply {
    val f = rootProject.file("keystore.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}

android {
    namespace = "com.deskrally.technician"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.deskrally.technician"
        minSdk = 24
        targetSdk = 37
        versionCode = 2
        versionName = "0.2.0"

        manifestPlaceholders["consoleHost"] = consoleHost
        buildConfigField("String", "CONSOLE_HOST", "\"$consoleHost\"")
        // The app-to-site half of Digital Asset Links (the site's /.well-known/assetlinks.json is
        // the other half). Backslash-escaped quotes: aapt treats a bare quote in a string resource
        // as a quoting toggle and would strip it.
        resValue(
            "string",
            "asset_statements",
            "[{\\\"relation\\\": [\\\"delegate_permission/common.handle_all_urls\\\"], " +
                "\\\"target\\\": {\\\"namespace\\\": \\\"web\\\", \\\"site\\\": \\\"https://$consoleHost\\\"}}]",
        )
    }

    buildFeatures {
        buildConfig = true
        resValues = true
    }

    signingConfigs {
        if (keystoreProps.containsKey("storeFile")) {
            create("release") {
                storeFile = file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfigs.findByName("release")?.let { signingConfig = it }
        }
        debug {
            // Debug builds use the SAME key so app links verify against the one fingerprint in
            // assetlinks.json; Android's auto-generated debug key would not match it.
            signingConfigs.findByName("release")?.let { signingConfig = it }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    lint {
        abortOnError = true
        warningsAsErrors = false
    }
}

dependencies {
    // docs/78: WebViewCompat.addWebMessageListener (the one console bridge).
    implementation("androidx.webkit:webkit:1.12.1")
    testImplementation("junit:junit:4.13.2")
}
