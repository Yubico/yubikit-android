/*
 * Copyright (C) 2025-2026 Yubico.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

plugins {
    alias(libs.plugins.android.library)
    id("yubikit-common")
}

android {
    compileSdk = 37

    defaultConfig {
        minSdk = 21

        testApplicationId = "com.yubico.yubikit.testing"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        testHandleProfiling = true
        testFunctionalTest = true

        multiDexEnabled = true
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        isCoreLibraryDesugaringEnabled = true
    }

    testOptions {
        targetSdk = 37
    }

    namespace = "com.yubico.yubikit.testing"
}

dependencies {
    // The SDK modules under test.
    api(project(":android"))
    api(project(":fido"))
    api(project(":piv"))
    api(project(":testing"))

    // Backports the java.* APIs logback-android needs at minSdk 21; required by
    // isCoreLibraryDesugaringEnabled above.
    coreLibraryDesugaring(libs.desugar.jdk.libs)

    // Theme parent, and TestActivity extends AppCompatActivity. Deliberately not
    // Material: its FocusRingDrawable aborts dex2oat on ART 5.0, so the test APK
    // will not install on API 21.
    implementation(libs.androidx.appcompat)

    // Instrumentation harness: AndroidJUnit4, ActivityScenario, the test runner.
    implementation(libs.androidx.junit)
    implementation(libs.androidx.test.core)
    implementation(libs.androidx.test.runner)

    // SLF4J binding. The SDK modules expose slf4j-api only, so tests pick one.
    implementation(libs.logback.android)
}

description = "This module contains instrumented test framework and tests for yubikit-android."

