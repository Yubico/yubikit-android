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
    java
    id("yubikit-java-convention")
    id("yubikit-common")
}

repositories {
    mavenCentral()
}

val integrationTest: SourceSet by sourceSets.creating {
    compileClasspath += sourceSets.named("main").get().output
    runtimeClasspath += sourceSets.named("main").get().output
}

configurations.named("integrationTestImplementation") {
    extendsFrom(configurations.named("implementation").get())
}
configurations.named("integrationTestRuntimeOnly") {
    extendsFrom(configurations.named("runtimeOnly").get())
}

dependencies {
    implementation(project(":desktop"))
    implementation(project(":piv"))
    implementation(project(":testing"))

    implementation(libs.bcpkix.jdk15to18)

    add("integrationTestImplementation", libs.junit.junit)
    add("integrationTestImplementation", libs.logback.classic)
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

tasks.register<Test>("integrationTest") {
    description = "Runs integration tests."
    group = "verification"
    testClassesDirs = integrationTest.output.classesDirs
    classpath = integrationTest.runtimeClasspath
    mustRunAfter(tasks.named("test"))
    testLogging.showStandardStreams = true

    // Forward yubikit.serial to the test JVM for device selection
    // Can be set via: -Dyubikit.serial=SERIAL on the command line,
    // in gradle.properties, or in Android Studio Run Configuration VM options
    listOf("yubikit.serial").forEach { prop ->
        System.getProperty(prop)?.let { systemProperty(prop, it) }
    }
    project.findProperty("yubikit.serial")?.let { systemProperty("yubikit.serial", it) }
}

description = "This module contains instrumented test framework and tests for yubikit-desktop."

