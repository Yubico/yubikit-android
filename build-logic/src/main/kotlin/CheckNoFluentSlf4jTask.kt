/*
 * Copyright (C) 2026 Yubico.
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

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.SkipWhenEmpty
import org.gradle.api.tasks.TaskAction

/**
 * Fails the build on any use of the SLF4J 2.x fluent logging API.
 *
 * See [FluentSlf4jDetector] for why the fluent API is banned and what to write instead.
 */
@CacheableTask
abstract class CheckNoFluentSlf4jTask : DefaultTask() {

    @get:InputFiles
    @get:SkipWhenEmpty
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val sources: ConfigurableFileCollection

    /** Written on success so Gradle can skip the task when nothing changed. */
    @get:OutputFile
    abstract val report: RegularFileProperty

    @TaskAction
    fun check() {
        val uses = FluentSlf4jDetector.scan(sources.files.sortedBy { it.path })
        if (uses.isNotEmpty()) {
            throw GradleException(FluentSlf4jDetector.describe(uses))
        }
        val output = report.get().asFile
        output.parentFile.mkdirs()
        output.writeText("Scanned ${sources.files.size} file(s), no fluent SLF4J calls found.\n")
    }
}
