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

import org.gradle.api.Action
import org.gradle.api.GradleException
import org.gradle.api.Project
import org.gradle.api.publish.PublishingExtension
import org.gradle.api.publish.maven.MavenPom
import org.gradle.plugins.signing.SigningExtension
import java.net.HttpURLConnection
import java.net.URI
import java.util.Base64

fun Project.configureSonatypeRepository(publishing: PublishingExtension) {
    publishing.repositories {
        maven {
            name = "sonatype"
            url =
                uri("https://ossrh-staging-api.central.sonatype.com/service/local/staging/deploy/maven2/")
            credentials {
                username = findProperty("sonatype.username")?.toString()
                password = findProperty("sonatype.password")?.toString()
            }
        }
    }
}

fun Project.configureSigning(signing: SigningExtension, publishing: PublishingExtension) {
    val isReleaseVersion = !version.toString().endsWith("SNAPSHOT")

    tasks.withType(org.gradle.plugins.signing.Sign::class.java).configureEach {
        onlyIf { isReleaseVersion && System.getenv("NO_GPG_SIGN") != "true" }
    }

    signing.apply {
        useGpgCmd()
        publishing.publications.findByName("maven")?.let { pub -> sign(pub) }
    }
}

fun Project.applyPomConfiguration(): Action<MavenPom> {
    return Action<MavenPom> {
        name.set("Yubico YubiKit " + project.name.replaceFirstChar { it.titlecase() })
        description.set(project.description)
        url.set("https://github.com/Yubico/yubikit-android/tree/main/${project.name}")
        licenses {
            license {
                name.set("The Apache License, Version 2.0")
                url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
            }
        }
        developers {
            developer {
                id.set("dainnilsson")
                name.set("Dain Nilsson")
                email.set("dain@yubico.com")
            }
        }
        scm {
            connection.set("scm:git:https://github.com/Yubico/yubikit-android.git")
            developerConnection.set("scm:git:ssh://github.com/Yubico/yubikit-android.git")
            url.set("https://github.com/Yubico/yubikit-android")
        }
    }
}

fun Project.registerFinalizeCentralPublicationTask() {
    // Register the task only once on the root project
    val rootProject = this.rootProject

    if (rootProject.tasks.findByName("finalizeCentralPublication") == null) {
        rootProject.tasks.register("finalizeCentralPublication") {
            description = "Notifies Sonatype Central that a manual publication is complete."
            group = "publishing"

            // Ensure this task runs after any publish task in the build
            rootProject.subprojects {
                tasks.matching { it.name == "publish" }.configureEach {
                    this@register.mustRunAfter(this)
                }
            }

            doLast {
                finalizeSonatypeCentralPublication(rootProject)
            }
        }
    }
}

private fun finalizeSonatypeCentralPublication(project: Project) {
    val sonatypeNamespace = "com.yubico"
    val sonatypeUserName = project.findProperty("sonatype.username") as String?
    val sonatypePassword = project.findProperty("sonatype.password") as String?
    val sonatypeBearerToken = "$sonatypeUserName:$sonatypePassword"
        .toByteArray()
        .let { Base64.getEncoder().encodeToString(it) }

    val url =
        URI("https://ossrh-staging-api.central.sonatype.com/manual/upload/defaultRepository/$sonatypeNamespace").toURL()

    project.logger.lifecycle("Finalizing publication by sending POST to $url")

    val connection = (url.openConnection() as HttpURLConnection).apply {
        requestMethod = "POST"
        setRequestProperty("Authorization", "Bearer $sonatypeBearerToken")
        setRequestProperty("User-Agent", "Gradle/${project.gradle.gradleVersion}")
        doOutput = true
    }

    val responseCode = connection.responseCode
    project.logger.lifecycle("Sonatype Central response: $responseCode ${connection.responseMessage}")

    if (responseCode !in 200..299) {
        val errorStream = connection.errorStream?.bufferedReader()?.readText()
        throw GradleException("Failed to finalize publication on Sonatype Central. Response: $responseCode. Body: $errorStream")
    }
}
