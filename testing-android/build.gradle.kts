/*
 * Copyright (C) 2025 Yubico.
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
    id("com.android.library")
    id("project-convention-common")
}

android {
    compileSdk = 36

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
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    testOptions {
        targetSdk = 36
    }

    namespace = "com.yubico.yubikit.testing"
}

dependencies {
    api(project(":android"))
    api(project(":fido"))
    api(project(":piv"))
    api(project(":testing"))

    coreLibraryDesugaring(libs.desugar.jdk.libs)

    implementation(libs.androidx.junit)
    implementation(libs.androidx.multidex)
    implementation(libs.androidx.test.core)
    implementation(libs.androidx.test.rules)
    implementation(libs.androidx.test.runner)

    implementation(libs.jsr305)
    implementation(libs.material)

    implementation(libs.logback.android)
}

description = "This module contains instrumented test framework and tests for yubikit-android."

