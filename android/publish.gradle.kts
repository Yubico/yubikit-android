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

import com.android.build.gradle.LibraryExtension
import org.gradle.api.Action
import org.gradle.api.publish.PublishingExtension
import org.gradle.api.publish.maven.MavenPom
import org.gradle.api.publish.maven.MavenPublication
import org.gradle.plugins.signing.Sign
import org.gradle.plugins.signing.SigningExtension

plugins.apply("maven-publish")
plugins.apply("signing")

val isReleaseVersion = !version.toString().endsWith("SNAPSHOT")
val android = extensions.getByType(LibraryExtension::class.java)

android.publishing {
    singleVariant("release") {
        withSourcesJar()
        withJavadocJar()
    }
}

afterEvaluate {
    extensions.configure(PublishingExtension::class.java) {
        publications {
            // If another script already registered, skip
            if (publications.findByName("maven") == null) {
                register("maven", MavenPublication::class.java) {
                    from(components.getByName("release"))
                    groupId = rootProject.group.toString()
                    artifactId = project.name
                    version = project.version.toString()
                    apply(from = rootProject.file("pom.gradle.kts"))
                    @Suppress("UNCHECKED_CAST")
                    val pomData = extra["pomData"] as Action<MavenPom>
                    pom(pomData)
                }
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
    extensions.configure(SigningExtension::class.java) {
        useGpgCmd()
        (extensions.getByType(PublishingExtension::class.java)
            .publications.findByName("maven"))?.let { pub -> sign(pub) }
    }
}

tasks.withType(Sign::class.java).configureEach {
    onlyIf { isReleaseVersion && System.getenv("NO_GPG_SIGN") != "true" }
}
