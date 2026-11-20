plugins {
  id("com.android.library") version "8.7.2"
  id("org.jetbrains.kotlin.android") version "2.0.21"
}

android {
  namespace = "dev.tendril"
  compileSdk = 35

  defaultConfig {
    minSdk = 26
    externalNativeBuild {
      cmake {
        arguments += "-DANDROID_ABI_RUST_TARGET=aarch64-linux-android"
      }
    }
    ndk {
      abiFilters += listOf("arm64-v8a")
    }
  }

  externalNativeBuild {
    cmake {
      path = file("jni/CMakeLists.txt")
      version = "3.22.1"
    }
  }

  compileOptions {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
  }

  kotlinOptions {
    jvmTarget = "17"
  }
}
