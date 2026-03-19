import com.diffplug.gradle.spotless.SpotlessExtension

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

// Applied imperatively to avoid classloader isolation issues with precompiled script plugins.
// Using `plugins { id("com.diffplug.spotless") }` causes each sibling project to get its own
// classloader for SpotlessTaskService, leading to build failures.
apply(plugin = "com.diffplug.spotless")

configure<SpotlessExtension> {
    java {
        target("src/*/java/**/*.java")
        googleJavaFormat("1.25.2")
        trimTrailingWhitespace()
        endWithNewline()
    }
    kotlin {
        target("**/*.kt")
        targetExclude("${layout.buildDirectory.get()}/**/*.kt")
        ktlint("1.2.1").editorConfigOverride(
            mapOf(
                "ktlint_function_naming_ignore_when_annotated_with" to "Composable"
            ),
        )
        trimTrailingWhitespace()
        endWithNewline()
    }
}