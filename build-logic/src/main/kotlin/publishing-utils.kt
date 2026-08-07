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
import org.gradle.api.publish.maven.MavenPublication
import org.gradle.plugins.signing.SigningExtension
import java.io.File

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

/**
 * Emergency local signing fallback for when the Scribe CI service is unavailable.
 *
 * When the `localSigning.gpgKey` project property is set (e.g.
 * `-PlocalSigning.gpgKey=0x1234ABCD`), the Gradle `signing` plugin is applied and the `maven`
 * publication is signed with the local `gpg` command, so `publishToMavenLocal` emits `.asc` files
 * that [registerCentralPortalPublishTask] then uploads. An empty value signs with gpg's default
 * key. Without the property nothing changes and signing is left to Scribe.
 *
 * Note: the Central Portal only validates a signature whose matching public key is discoverable on
 * a public keyserver (e.g. keys.openpgp.org).
 */
fun Project.configureLocalGpgSigning(publishing: PublishingExtension) {
    val gpgKey = findProperty("localSigning.gpgKey") as String? ?: return
    pluginManager.apply("signing")
    val signing = extensions.getByType(SigningExtension::class.java)
    signing.useGpgCmd()
    if (gpgKey.isNotBlank()) {
        extensions.extraProperties["signing.gnupg.keyName"] = gpgKey
    }
    (publishing.publications.findByName("maven") as? MavenPublication)?.let { signing.sign(it) }
}

/**
 * Registers the root `publishToCentralPortal` task, which uploads the Scribe-signed artifacts from
 * a local Maven repository to the Sonatype Central Publisher Portal.
 *
 * Unlike the `maven-publish` plugin (which ignores externally produced `.asc` signatures), this
 * bundles the whole signed repository tree — signatures included — and uploads it in a single
 * request, so the signatures reach Central.
 */
fun Project.registerCentralPortalPublishTask() {
    val rootProject = this.rootProject
    if (rootProject.tasks.findByName("publishToCentralPortal") != null) return

    rootProject.tasks.register("publishToCentralPortal") {
        description = "Uploads Scribe-signed artifacts from a local Maven repo to Sonatype Central."
        group = "publishing"

        doLast {
            val username = rootProject.findProperty("sonatype.username") as String?
                ?: throw GradleException("Missing 'sonatype.username' (see doc/publish.adoc)")
            val password = rootProject.findProperty("sonatype.password") as String?
                ?: throw GradleException("Missing 'sonatype.password' (see doc/publish.adoc)")

            val repoRoot = File(
                (rootProject.findProperty("centralPortal.repoDir") as String?)
                    ?: "${System.getProperty("user.home")}/.m2/repository"
            )
            val groupPath = rootProject.group.toString().replace('.', '/')
            val publishingType =
                (rootProject.findProperty("centralPortal.publishingType") as String?) ?: "USER_MANAGED"
            val deploymentName = (rootProject.findProperty("centralPortal.deploymentName") as String?)
                ?: "${rootProject.group} (manual upload)"

            val bundle = rootProject.layout.buildDirectory
                .file("central-portal/bundle.zip").get().asFile

            val uploader = CentralPortalUploader()
            uploader.createBundle(repoRoot, groupPath, bundle)
            rootProject.logger.lifecycle(
                "Uploading ${bundle.length()} byte bundle from ${repoRoot.resolve(groupPath)} to Central Portal"
            )
            val deploymentId = uploader.upload(bundle, username, password, deploymentName, publishingType)
            rootProject.logger.lifecycle("Central Portal deployment created: $deploymentId")
            rootProject.logger.lifecycle(
                "Track and publish it at https://central.sonatype.com/publishing/deployments"
            )
        }
    }
}
