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
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.spotless) apply false
}

fun VersionCatalog.javaVersion(): JavaVersion =
    JavaVersion.toVersion(this.findVersion("java").get().requiredVersion)

allprojects {
    gradle.projectsEvaluated {
        tasks.withType<JavaCompile>().configureEach {
            options.compilerArgs.addAll(listOf("-Xlint:deprecation", "-Xlint:unchecked"))
        }
    }
    group = "com.yubico.yubikit"
}

// Single source of truth for the published library version. The release workflow
// cross-checks this against the release-candidate tag that triggered it, so the
// two cannot drift apart.
val libraryVersion = "3.2.1-SNAPSHOT"

subprojects {
    version = libraryVersion
    tasks.withType<Javadoc>().configureEach {
        (options as? StandardJavadocDocletOptions)?.addStringOption(
            "Xdoclint:all,-missing",
            "-quiet"
        )
    }
}

// Consumed by the release workflow to verify the tag against the version being built.
tasks.register("printVersion") {
    group = "help"
    description = "Prints the library version to stdout."
    val libVersion = libraryVersion
    doLast { println(libVersion) }
}
