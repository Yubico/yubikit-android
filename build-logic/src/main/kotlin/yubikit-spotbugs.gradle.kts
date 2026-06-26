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

import com.android.build.api.dsl.LibraryExtension
import java.io.ByteArrayOutputStream
import java.util.Properties

plugins {
    `java-base`
}

// Delay accessing libs until afterEvaluate
val libs: VersionCatalog by lazy { the<VersionCatalogsExtension>().named("libs") }

// Create a separate configuration ONLY for running SpotBugs (not compile-time)
val spotbugsRuntime: Configuration by configurations.creating {
    isCanBeConsumed = false
    isCanBeResolved = true
    isTransitive = true
}

// Add dependencies in afterEvaluate to avoid build-logic issues
afterEvaluate {
    dependencies {
        spotbugsRuntime(libs.findLibrary("spotbugs").get())
        spotbugsRuntime(libs.findLibrary("findsecbugs-plugin").get())
        spotbugsRuntime(libs.findLibrary("spotbugs-annotations").get())

        spotbugsRuntime(libs.findLibrary("jsr305").get())
        spotbugsRuntime(libs.findLibrary("jsr250-api").get())

        spotbugsRuntime(libs.findLibrary("slf4j-nop").get())
    }
}

// Common function to find classes directory
fun findClassesDir(project: Project, isAndroid: Boolean): File? {
    val buildDir = project.layout.buildDirectory.asFile.get()
    return if (isAndroid) {
        listOf(
            // Java classes (AGP)
            File("$buildDir/intermediates/javac/release/compileReleaseJavaWithJavac/classes"),
            File("$buildDir/intermediates/javac/release/classes"),
            File("$buildDir/intermediates/classes/release"),
            // Kotlin classes (AGP 9.x)
            File("$buildDir/intermediates/built_in_kotlinc/release/compileReleaseKotlin/classes"),
            // Bundled classes JAR (fallback)
            File("$buildDir/intermediates/compile_library_classes_jar/release/bundleLibCompileToJarRelease/classes.jar")
        ).firstOrNull { it.exists() }
    } else {
        File("$buildDir/classes/java/main").takeIf { it.exists() }
    }
}

// Common function to create SpotBugs task
fun createSpotBugsTask(
    project: Project,
    spotbugsRuntime: Configuration,
    spotbugsAuxClasspath: FileCollection,
    isAndroid: Boolean,
    reportFormat: String = "html"
) {
    val taskSuffix = if (isAndroid) "Release" else "Main"
    val taskDescription = if (isAndroid) "release" else "main"
    val formatSuffix = if (reportFormat == "sarif") "Sarif" else "Html"
    val outputExt = if (reportFormat == "sarif") "sarif" else "html"

    project.tasks.register<Exec>("spotbugs$taskSuffix$formatSuffix") {
        group = "verification"
        description = "Run SpotBugs analysis on $taskDescription code (${reportFormat.uppercase()})"

        val reportDir = File("${project.rootDir}/build/spotbugs")
        val htmlDir = File("${project.rootDir}/build/spotbugs-html")
        reportDir.mkdirs()
        htmlDir.mkdirs()

        doFirst {
            val spotbugsClasspath = spotbugsRuntime.joinToString(":") { it.absolutePath }
            logger.lifecycle("[${project.name}] SpotBugs Classpath: ${spotbugsRuntime.files.size} files")

            val auxClasspath = spotbugsAuxClasspath.joinToString(":") { it.absolutePath }
            if (auxClasspath.isNotEmpty()) {
                logger.lifecycle("[${project.name}] SpotBugs Aux Classpath: ${spotbugsAuxClasspath.files.size} files")
            }

            val classesDir = findClassesDir(project, isAndroid)

            if (classesDir == null || !classesDir.exists()) {
                logger.warn("[${project.name}] Classes directory not found. Skipping analysis.")
                throw StopExecutionException("No classes directory found for ${project.name}")
            }

            val outputDir = if (reportFormat == "sarif") reportDir else htmlDir
            val outputFile = File(outputDir, "spotbugs-${project.name}.$outputExt")
            val excludeFile = File("${project.rootDir}/spotbugs/excludeFilter.xml")

            // Find the findsecbugs plugin JAR and extract version
            val findSecBugsJar = spotbugsRuntime.files.find { it.name.contains("findsecbugs") }
            val pluginPath = findSecBugsJar?.absolutePath ?: ""
            val pluginVersion =
                findSecBugsJar?.name?.substringAfterLast("-")?.removeSuffix(".jar") ?: "unknown"

            val cmdList = mutableListOf(
                "java",
                "-cp",
                spotbugsClasspath,
                "edu.umd.cs.findbugs.FindBugs2",
                "-effort:more",
                "-high",
                "-$reportFormat",
                "-output",
                outputFile.absolutePath
            )

            // Add plugin path if found
            if (pluginPath.isNotEmpty()) {
                cmdList.addAll(listOf("-pluginList", pluginPath))
                logger.lifecycle("[${project.name}] Using FindSecBugs plugin: v$pluginVersion")
                logger.debug("[${project.name}] FindSecBugs plugin path: $pluginPath")
            }

            if (auxClasspath.isNotEmpty()) {
                cmdList.addAll(listOf("-auxclasspath", auxClasspath))
            }

            if (excludeFile.exists()) {
                cmdList.addAll(listOf("-exclude", excludeFile.absolutePath))
            }

            cmdList.add(classesDir.absolutePath)

            commandLine = cmdList
            standardOutput = ByteArrayOutputStream()
        }

        isIgnoreExitValue = true

        doLast {
            val outputDir = if (reportFormat == "sarif") {
                File("${project.rootDir}/build/spotbugs")
            } else {
                File("${project.rootDir}/build/spotbugs-html")
            }
            logger.lifecycle("[${project.name}] SpotBugs ${reportFormat.uppercase()} analysis completed")
            logger.lifecycle("  Report: ${outputDir}/spotbugs-${project.name}.$outputExt")
        }
    }
}

// Determine project type and configure accordingly
afterEvaluate {
    val isAndroidLibrary = project.plugins.hasPlugin("com.android.library")
    val isAndroidApp = project.plugins.hasPlugin("com.android.application")
    val isJavaLibrary =
        project.plugins.hasPlugin("java-library") || project.plugins.hasPlugin("java")

    when {
        isAndroidLibrary && !project.name.contains("test", ignoreCase = true) -> {
            // Android Library (not a test module)
            logger.lifecycle("Configuring SpotBugs for Android Library: ${project.name}")

            // Use an ArtifactView on releaseRuntimeClasspath with artifactType filter
            // to resolve the AGP 9.x variant ambiguity for project-to-project dependencies.
            val depsClasspath: FileCollection = try {
                val releaseClasspath = configurations.getByName("releaseRuntimeClasspath")
                releaseClasspath.incoming.artifactView {
                    attributes {
                        attribute(
                            ArtifactTypeDefinition.ARTIFACT_TYPE_ATTRIBUTE,
                            "android-classes-jar"
                        )
                    }
                    lenient(true)
                }.files
            } catch (e: Exception) {
                logger.debug("Could not find releaseRuntimeClasspath: ${e.message}")
                files()
            }

            // Include Android SDK (android.jar) so SpotBugs can resolve android.* classes
            val bootClasspath: FileCollection = try {
                val androidExt = extensions.getByType(LibraryExtension::class.java)
                val compileSdk = androidExt.compileSdk

                // Resolve Android SDK path from ANDROID_HOME or local.properties
                var sdkDir: File? = null
                val envHome = System.getenv("ANDROID_HOME")
                val envRoot = System.getenv("ANDROID_SDK_ROOT")
                if (envHome != null) {
                    sdkDir = File(envHome)
                } else if (envRoot != null) {
                    sdkDir = File(envRoot)
                } else {
                    val propsFile = project.rootDir.resolve("local.properties")
                    if (propsFile.exists()) {
                        val props = Properties()
                        propsFile.inputStream().use { stream -> props.load(stream) }
                        val sdkPath = props.getProperty("sdk.dir")
                        if (sdkPath != null) {
                            sdkDir = File(sdkPath)
                        }
                    }
                }

                val resolvedSdkDir = sdkDir
                if (resolvedSdkDir != null && compileSdk != null) {
                    val androidJar = File(resolvedSdkDir, "platforms/android-$compileSdk/android.jar")
                    if (androidJar.exists()) files(androidJar) else {
                        logger.debug("android.jar not found at: $androidJar")
                        files()
                    }
                } else {
                    logger.debug("Could not determine Android SDK directory or compileSdk")
                    files()
                }
            } catch (e: Exception) {
                logger.debug("Could not get Android bootClasspath: ${e.message}")
                files()
            }

            val auxClasspathFiles = depsClasspath + bootClasspath

            createSpotBugsTask(project, spotbugsRuntime, auxClasspathFiles, true, "html")
            createSpotBugsTask(project, spotbugsRuntime, auxClasspathFiles, true, "sarif")
        }

        isAndroidApp || (isAndroidLibrary && project.name.contains("test", ignoreCase = true)) -> {
            // Android App or Test Module (skip aux classpath)
            logger.lifecycle("Configuring SpotBugs for Android App/Test: ${project.name}")

            createSpotBugsTask(project, spotbugsRuntime, files(), true, "html")
            createSpotBugsTask(project, spotbugsRuntime, files(), true, "sarif")
        }

        isJavaLibrary -> {
            // Java Library
            logger.lifecycle("Configuring SpotBugs for Java Library: ${project.name}")

            val auxClasspathFiles: FileCollection = try {
                configurations.getByName("compileClasspath")
            } catch (e: Exception) {
                logger.debug("Could not find compileClasspath: ${e.message}")
                files()
            }

            createSpotBugsTask(project, spotbugsRuntime, auxClasspathFiles, false, "html")
            createSpotBugsTask(project, spotbugsRuntime, auxClasspathFiles, false, "sarif")
        }

        else -> {
            logger.debug("Project ${project.name} is not a recognized type for SpotBugs")
        }
    }
}

// Register root-level aggregate tasks (only once on root project)
if (!rootProject.tasks.names.contains("spotbugsSarif")) {
    rootProject.tasks.register("spotbugsSarif") {
        group = "verification"
        description = "Run SpotBugs on all modules (SARIF reports only)"

        rootProject.subprojects {
            listOf("Main", "Release").forEach { variant ->
                val sarifTask = tasks.findByPath(":${this.name}:spotbugs${variant}Sarif")
                if (sarifTask != null) {
                    dependsOn(sarifTask)
                }
            }
        }
    }

    rootProject.tasks.register("spotbugsHtml") {
        group = "verification"
        description = "Run SpotBugs on all modules (HTML reports only)"

        rootProject.subprojects {
            listOf("Main", "Release").forEach { variant ->
                val htmlTask = tasks.findByPath(":${this.name}:spotbugs${variant}Html")
                if (htmlTask != null) {
                    dependsOn(htmlTask)
                }
            }
        }
    }

    rootProject.tasks.register("spotbugs") {
        group = "verification"
        description = "Run SpotBugs on all modules (both SARIF and HTML reports)"

        dependsOn("spotbugsSarif", "spotbugsHtml")
    }
}

// Make spotbugs tasks depend on build
afterEvaluate {
    listOf("Main", "Release").forEach { variant ->
        tasks.findByName("spotbugs${variant}Sarif")?.dependsOn("build")
        tasks.findByName("spotbugs${variant}Html")?.dependsOn("build")
    }
}