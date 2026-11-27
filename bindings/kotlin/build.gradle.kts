plugins {
  id("com.android.library") version "9.5.3"
  id("maven-publish")
}

android {
  namespace = "dev.tendril"
  compileSdk = 35

  defaultConfig {
    minSdk = 26
    testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    consumerProguardFiles("consumer-rules.pro")
    externalNativeBuild {
      cmake {
        arguments += "-DANDROID_ABI_RUST_TARGET=aarch64-linux-android"
      }
    }
    ndk {
      abiFilters += listOf("arm64-v8a")
    }
  }

  if (!hasProperty("prebuiltAar")) {
    externalNativeBuild {
      cmake {
        path = file("jni/CMakeLists.txt")
        version = "3.22.1"
      }
    }
  }

  compileOptions {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
  }

  publishing {
    singleVariant("release") {
      withSourcesJar()
    }
  }
}

afterEvaluate {
  val prebuiltAar = (findProperty("prebuiltAar") as String?)?.takeIf { it.isNotBlank() }
  val resolvedVersion = (findProperty("tendrilVersion") as String?) ?: "0.1.0" // x-release-please-version

  fun MavenPublication.configureTendrilPublication() {
    groupId = "dev.agync"
    artifactId = "tendril-android"
    version = resolvedVersion
    pom {
      name.set("Tendril Android SDK")
      description.set("Android Kotlin JNI bindings for Tendril private device-to-device links.")
      url.set("https://tendril.agync.dev")
      licenses {
        license {
          name.set("Apache-2.0")
          url.set("https://www.apache.org/licenses/LICENSE-2.0")
        }
      }
      scm {
        url.set("https://github.com/agync/tendril")
      }
    }
  }

  publishing {
    publications {
      if (prebuiltAar != null) {
        register<MavenPublication>("prebuiltRelease") {
          configureTendrilPublication()
          artifact(file(prebuiltAar)) {
            extension = "aar"
          }
        }
      } else {
        register<MavenPublication>("release") {
          configureTendrilPublication()
          from(components["release"])
        }
      }
    }
    repositories {
      maven {
        name = "GitHubPackages"
        url = uri("https://maven.pkg.github.com/agync/tendril")
        credentials {
          username = System.getenv("GITHUB_ACTOR") ?: ""
          password = System.getenv("GITHUB_TOKEN") ?: ""
        }
      }
    }
  }
}

dependencies {
  testImplementation("junit:junit:4.13.2")
  androidTestImplementation("androidx.test.ext:junit:1.2.1")
  androidTestImplementation("androidx.test:runner:1.6.2")
  androidTestImplementation("androidx.test:rules:1.6.1")
  androidTestImplementation("com.google.zxing:core:3.5.4")
  androidTestImplementation("com.google.mlkit:barcode-scanning:17.3.0")
}
