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
    application
    id("yubikit-spotbugs")
    id("yubikit-spotless")
}

dependencies {
    implementation(project(":desktop"))
    implementation(project(":oath"))
    implementation(project(":fido"))
    implementation(project(":yubiotp"))

    compileOnly(libs.jsr305)

    implementation(libs.logback.classic)
}

application {
    mainClass.set("com.yubico.yubikit.desktop.app.DesktopApp")
    applicationName = "DesktopApp"
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

