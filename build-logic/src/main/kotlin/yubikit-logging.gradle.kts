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

val libs: VersionCatalog = extensions.getByType<VersionCatalogsExtension>().named("libs")

dependencies {
    add("api", libs.findLibrary("slf4j-api").get())
}

// slf4j-api is exposed on the `api` configuration above, so the fluent logging API is in reach of
// every module this plugin touches. It cannot be used - see FluentSlf4jDetector - so guard against
// it here, where the dependency is introduced.
val checkNoFluentSlf4j =
    tasks.register<CheckNoFluentSlf4jTask>("checkNoFluentSlf4j") {
        group = "verification"
        description = "Fails on uses of the SLF4J fluent logging API, which D8 cannot desugar."
        sources.from(fileTree("src") { include("**/*.java", "**/*.kt") })
        report.set(layout.buildDirectory.file("reports/logging/no-fluent-slf4j.txt"))
    }

tasks.matching { it.name == "check" }.configureEach { dependsOn(checkNoFluentSlf4j) }