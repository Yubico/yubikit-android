/*
 * Copyright (C) 2024-2025 Yubico.
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

import com.github.spotbugs.snom.Confidence
import com.github.spotbugs.snom.Effort

plugins {
    id("com.github.spotbugs")
}

val libs = extensions.getByType<VersionCatalogsExtension>().named("libs")

dependencies {
    spotbugs(libs.findLibrary("spotbugs").get())
    spotbugsPlugins(libs.findLibrary("findsecbugs-plugin").get())

    add("compileOnly", libs.findLibrary("spotbugs-annotations").get())
}

spotbugs {
    ignoreFailures = true
    showStackTraces = false
    showProgress = false

    effort = Effort.MORE
    reportLevel = Confidence.valueOf("DEFAULT")
    excludeFilter = file("../spotbugs/excludeFilter.xml")
}

tasks.withType<com.github.spotbugs.snom.SpotBugsTask> {
    when(name) {
        "spotbugsTest" -> enabled = false
        "spotbugsMain", "spotbugsRelease" -> {
            enabled = true
            reports.create("html") {
                outputLocation =
                    file("${project.rootDir}/build/spotbugs-html/spotbugs-${project.name}.html")
            }
            reports.create("sarif") {
                outputLocation =
                    file("${project.rootDir}/build/spotbugs/spotbugs-${project.name}.sarif")
            }
        }
    }
}