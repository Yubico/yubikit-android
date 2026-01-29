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

import com.android.build.api.dsl.ManagedVirtualDevice
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.android.library)
    alias(libs.plugins.ksp)
    id("yubikit-android-publishing")
    id("yubikit-common")
}

ext.set("customPom", true)

android {
    namespace = "com.yubico.yubikit.fido.android"
    compileSdk = 36

    defaultConfig {
        minSdk = 23

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
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

        explicitApi()
    }

    buildFeatures {
        compose = true
    }

    @Suppress("UnstableApiUsage")
    testOptions {
        managedDevices {
            allDevices {
                create("smallPhone", ManagedVirtualDevice::class) {
                    device = "Pixel 4"
                    apiLevel = 36
                    systemImageSource = "aosp"
                }
                create("largePhone", ManagedVirtualDevice::class) {
                    device = "Pixel 7 Pro"
                    apiLevel = 36
                    systemImageSource = "aosp"
                }
                create("tablet", ManagedVirtualDevice::class) {
                    device = "Pixel C"
                    apiLevel = 36
                    systemImageSource = "aosp"
                }
            }
            groups {
                create("allDevicesGroup") {
                    targetDevices.addAll(
                        listOf(
                            allDevices.getByName("smallPhone"),
                            allDevices.getByName("largePhone"),
                            allDevices.getByName("tablet")
                        )
                    )
                }
            }
        }

        unitTests {
            isIncludeAndroidResources = true
        }
    }
}

afterEvaluate {
    publishing {
        publications {
            named<MavenPublication>("maven") {
                pom {
                    name.set("Yubico YubiKit FIDO Android")
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
    api(project(":fido"))

    implementation(libs.androidx.fragment.ktx)
    implementation(libs.androidx.webkit)

    val composeBom = platform(libs.androidx.compose.bom)
    implementation(composeBom)
    androidTestImplementation(composeBom)
    testImplementation(composeBom)

    implementation(libs.kotlin.stdlib.jdk8)
    implementation(libs.androidx.material3)

    // Android Studio Preview support
    implementation(libs.androidx.ui.tooling.preview)
    debugImplementation(libs.androidx.ui.tooling)

    // UI Tests
    androidTestImplementation(libs.androidx.ui.test.junit4)
    implementation(libs.androidx.ui.test.manifest)

    implementation(libs.androidx.material.icons.core)
    implementation(libs.androidx.runtime.livedata)
    implementation(libs.androidx.material.icons.extended)
    implementation(libs.androidx.adaptive)

    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.activity.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.viewmodel.ktx)
    implementation(libs.androidx.runtime.livedata)
    implementation(libs.androidx.appcompat)
    implementation(libs.kotlinx.serialization.json)

    // testing dependencies
    testImplementation(libs.junit.junit)
    testImplementation(libs.mockito)
    testImplementation(libs.mockito.kotlin)
    testImplementation(libs.turbine)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.robolectric)
    testImplementation(libs.ui.test.junit4)
    testImplementation(libs.androidx.test.core)
    testImplementation(libs.slf4j.api)
    testRuntimeOnly(libs.logback.classic)

    // Instrumented test dependencies
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.test.rules)
}

description = "This module provides user interface for YubiKit FIDO module."