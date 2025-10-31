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
import java.net.HttpURLConnection
import java.net.URI
import java.util.Base64

plugins {
    `maven-publish`
    signing
}

val isReleaseVersion = !version.toString().endsWith("SNAPSHOT")

extensions.getByType(JavaPluginExtension::class.java).apply {
    withJavadocJar()
    withSourcesJar()
}

extensions.configure(PublishingExtension::class.java) {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            apply(from = rootProject.file("pom.gradle.kts"))
            @Suppress("UNCHECKED_CAST")
            val pomData = extra["pomData"] as Action<MavenPom>
            pom(pomData)
        }
    }
    repositories {
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

tasks.withType(Sign::class.java).configureEach {
    onlyIf { isReleaseVersion && System.getenv("NO_GPG_SIGN") != "true" }
}

extensions.configure(SigningExtension::class.java) {
    useGpgCmd()
    sign(extensions.getByType(PublishingExtension::class.java).publications["maven"])
}

// Custom task to notify Sonatype Central that the manual upload is complete.
tasks.register("finalizeCentralPublication") {
    description = "Notifies Sonatype Central that a manual publication is complete."
    group = "publishing"

    doLast {
        // Retrieve credentials securely from gradle.properties or environment variables.
        val sonatypeNamespace = "com.yubico"
        val sonatypeUserName = findProperty("sonatype.username") as String?
        val sonatypePassword = findProperty("sonatype.password") as String?
        val sonatypeBearerToken = "$sonatypeUserName:$sonatypePassword"
            .toByteArray()
            .let { Base64.getEncoder().encodeToString(it) }

        // Construct the API endpoint URL.
        val url =
            URI("https://ossrh-staging-api.central.sonatype.com/manual/upload/defaultRepository/$sonatypeNamespace").toURL()

        logger.lifecycle("Finalizing publication by sending POST to $url")

        // Open a connection and configure the POST request.
        val connection = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            setRequestProperty("Authorization", "Bearer $sonatypeBearerToken")
            setRequestProperty("User-Agent", "Gradle/${project.gradle.gradleVersion}")
            doOutput = true // Necessary for a POST request.
        }

        val responseCode = connection.responseCode
        logger.lifecycle("Sonatype Central response: $responseCode ${connection.responseMessage}")

        // Check if the request was successful. If not, fail the build.
        if (responseCode !in 200..299) {
            val errorStream = connection.errorStream?.bufferedReader()?.readText()
            throw GradleException("Failed to finalize publication on Sonatype Central. Response: $responseCode. Body: $errorStream")
        }

        logger.lifecycle("Successfully finalized publication on Sonatype Central.")
    }
}