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

    sourceSets {
        getByName("test") {
            java.srcDirs("src/test/java", "src/test/kotlin")
        }
    }

    testOptions {
        unitTests {
            isReturnDefaultValues = true
        }
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

val syncTestClassesToAsciiDir = tasks.register("syncTestClassesToAsciiDir") {
    dependsOn("compileDebugUnitTestKotlin", "compileDebugUnitTestJavaWithJavac", "compileDebugKotlin")
    doLast {
        val targetDir = File(System.getProperty("user.home"), ".reconbridge_test_classes")
        if (targetDir.exists()) targetDir.deleteRecursively()
        targetDir.mkdirs()

        val sources = listOf(
            layout.buildDirectory.dir("tmp/kotlin-classes/debugUnitTest").get().asFile,
            layout.buildDirectory.dir("intermediates/javac/debugUnitTest/compileDebugUnitTestJavaWithJavac/classes").get().asFile,
            layout.buildDirectory.dir("tmp/kotlin-classes/debug").get().asFile
        )
        for (src in sources) {
            if (src.exists()) {
                src.copyRecursively(targetDir, overwrite = true)
            }
        }
    }
}

afterEvaluate {
    tasks.withType<Test>().configureEach {
        dependsOn(syncTestClassesToAsciiDir)
        val asciiDir = File(System.getProperty("user.home"), ".reconbridge_test_classes")
        testClassesDirs = files(asciiDir)
        classpath = files(asciiDir) + classpath
    }
}

dependencies {
    // Xposed API：仅编译期依赖，运行时由 LSPosed 提供
    compileOnly("de.robv.android.xposed:api:82")
    implementation("org.mozilla:rhino:1.7.15")

    testImplementation("de.robv.android.xposed:api:82")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}
