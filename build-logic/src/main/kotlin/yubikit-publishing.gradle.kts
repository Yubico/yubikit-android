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
plugins {
    `maven-publish`
    signing
}

extensions.getByType(JavaPluginExtension::class.java).apply {
    withJavadocJar()
    withSourcesJar()
}

val publishing = extensions.getByType(PublishingExtension::class.java)
val signing = extensions.getByType(SigningExtension::class.java)

publishing.publications {
    create<MavenPublication>("maven") {
        from(components["java"])
        afterEvaluate {
            pom(applyPomConfiguration())
        }
    }
}

configureSonatypeRepository(publishing)
configureSigning(signing, publishing)
registerFinalizeCentralPublicationTask()