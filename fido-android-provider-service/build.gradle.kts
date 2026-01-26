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

import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlinx.serialization)
    id("yubikit-android-publishing")
    id("yubikit-common")
}

ext.set("customPom", true)

repositories {
    google()
    mavenCentral()
}

android {
    namespace = "com.yubico.yubikit.fido.android.providerservice"
    compileSdk = 36

    defaultConfig {
        minSdk = 34
        testInstrumentationRunner = "android.support.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    kotlin {
        compilerOptions {
            jvmTarget = JvmTarget.JVM_11
        }
    }

    buildFeatures {
        compose = true
    }
}

afterEvaluate {
    publishing {
        publications {
            named<MavenPublication>("maven") {
                pom {
                    name.set("Yubico FIDO2 Provider Service")
                    description.set(project.description)
                    url.set("https://github.com/Yubico/yubikit-android")

                    licenses {
                        license {
                            name.set("The Apache License, Version 2.0")
                            url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                        }
                    }

                    developers {
                        developer {
                            id.set("adamve")
                            name.set("Adam Velebil")
                            email.set("adam.velebil@yubico.com")
                        }
                    }

                    scm {
                        connection.set("scm:git:https://github.com/Yubico/yubikit-android.git")
                        developerConnection.set("scm:git:ssh://github.com/Yubico/yubikit-android.git")
                        url.set("https://github.com/Yubico/yubikit-android")
                    }
                }
            }
        }
    }
}

dependencies {
    implementation(project(":android"))
    implementation(project(":fido-android"))

    implementation(libs.androidx.activity.ktx)
    implementation(libs.androidx.credentials)

    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.material3)
    implementation(libs.androidx.lifecycle.viewmodel.compose)

    implementation(libs.bcpkix.jdk15to18)
    implementation(libs.logback.android)

    implementation(libs.kotlinx.serialization.json)

    testImplementation(libs.junit.junit)
}

description = "This library implements Credential Provider Service with YubiKit Fido2 functionality"