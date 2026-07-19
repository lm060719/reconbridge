plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.reconbridge.tracer"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.reconbridge.tracer"
        minSdk = 27
        targetSdk = 34
        versionCode = 2
        versionName = "1.0.1"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
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

dependencies {
    // Xposed API：仅编译期依赖，运行时由 LSPosed 提供
    compileOnly("de.robv.android.xposed:api:82")
}
