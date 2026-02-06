/*
 * Copyright (C) 2024-2026 Yubico.
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

import com.android.build.api.dsl.ApplicationExtension
import com.android.build.api.dsl.LibraryExtension

plugins {
    // no AGP9 support yet id("yubikit-spotbugs")
    id("yubikit-spotless")
    id("yubikit-logging")
    id("yubikit-jspecify")
}

val versionCatalog = extensions.getByType(VersionCatalogsExtension::class.java).named("libs")
val javaVersionString = versionCatalog.findVersion("java").get().requiredVersion
val javaVersion = JavaVersion.toVersion(javaVersionString)

// Apply to both Android and Java projects
plugins.withId("com.android.library") {
    configure<LibraryExtension> {
        compileOptions {
            sourceCompatibility = javaVersion
            targetCompatibility = javaVersion
        }
    }
}

plugins.withId("com.android.application") {
    configure<ApplicationExtension> {
        compileOptions {
            sourceCompatibility = javaVersion
            targetCompatibility = javaVersion
        }
    }
}

plugins.withId("java") {
    tasks.withType<JavaCompile> {
        sourceCompatibility = javaVersion.toString()
        targetCompatibility = javaVersion.toString()
    }
}