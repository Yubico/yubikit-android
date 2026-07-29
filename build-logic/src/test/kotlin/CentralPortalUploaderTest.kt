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

import java.io.File
import java.security.MessageDigest
import java.util.Base64
import java.util.zip.ZipFile
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class CentralPortalUploaderTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val groupPath = "com/yubico/yubikit"

    /** Records what it was asked to upload and returns a canned response. */
    private class RecordingTransport(private val response: CentralPortalResponse) :
        CentralPortalTransport {
        var uploadUrl: String? = null
        var authorization: String? = null
        var deploymentName: String? = null
        var publishingType: String? = null
        var bundle: File? = null

        override fun uploadBundle(
            uploadUrl: String,
            authorization: String,
            deploymentName: String?,
            publishingType: String,
            bundle: File,
        ): CentralPortalResponse {
            this.uploadUrl = uploadUrl
            this.authorization = authorization
            this.deploymentName = deploymentName
            this.publishingType = publishingType
            this.bundle = bundle
            return response
        }
    }

    private fun artifactDir(): File =
        tmp.newFolder("repo", "com", "yubico", "yubikit", "core", "1.0.0")

    @Test
    fun createBundle_preservesLayoutAndSignaturesAndGeneratesChecksums() {
        val repoRoot = File(tmp.root, "repo")
        val dir = artifactDir()
        val jar = File(dir, "core-1.0.0.jar").apply { writeText("jar-bytes") }
        File(dir, "core-1.0.0.pom").writeText("<project/>")
        File(dir, "core-1.0.0.module").writeText("{}")
        File(dir, "core-1.0.0.jar.asc").writeText("signature-jar")
        File(dir, "core-1.0.0.pom.asc").writeText("signature-pom")
        // A checksum that already exists must be preserved verbatim, not regenerated.
        File(dir, "core-1.0.0.jar.md5").writeText("preexisting-md5")

        val bundle = File(tmp.root, "bundle.zip")
        CentralPortalUploader().createBundle(repoRoot, groupPath, bundle)

        val entries = ZipFile(bundle).use { zip -> zip.entries().toList().associateBy { it.name } }
        val base = "$groupPath/core/1.0.0/core-1.0.0"

        // Artifacts and their signatures are all present, in Maven layout.
        assertNotNull(entries["$base.jar"])
        assertNotNull(entries["$base.pom"])
        assertNotNull(entries["$base.module"])
        assertNotNull("jar signature must be preserved", entries["$base.jar.asc"])
        assertNotNull("pom signature must be preserved", entries["$base.pom.asc"])

        // Missing checksums are generated for artifacts...
        assertNotNull(entries["$base.jar.sha1"])
        assertNotNull(entries["$base.pom.md5"])
        assertNotNull(entries["$base.pom.sha1"])
        assertNotNull(entries["$base.module.md5"])
        assertNotNull(entries["$base.module.sha1"])

        // ...but not for signatures or existing checksums.
        assertNull(entries["$base.jar.asc.md5"])
        assertNull(entries["$base.jar.asc.sha1"])
        assertNull(entries["$base.jar.md5.md5"])

        ZipFile(bundle).use { zip ->
            // Pre-existing checksum is kept as-is (appears once, unchanged).
            assertEquals(
                "preexisting-md5",
                zip.getInputStream(entries["$base.jar.md5"]).bufferedReader().readText(),
            )
            // Generated checksum matches an independently computed digest of the artifact.
            assertEquals(
                sha1Hex(jar.readBytes()),
                zip.getInputStream(entries["$base.jar.sha1"]).bufferedReader().readText(),
            )
        }
    }

    @Test
    fun createBundle_failsWhenNoArtifacts() {
        val repoRoot = tmp.newFolder("empty-repo")
        val ex = assertThrows(IllegalArgumentException::class.java) {
            CentralPortalUploader().createBundle(repoRoot, groupPath, File(tmp.root, "b.zip"))
        }
        assertTrue(ex.message!!.contains(groupPath))
    }

    @Test
    fun upload_returnsDeploymentIdAndSendsExpectedRequest() {
        val transport = RecordingTransport(CentralPortalResponse(201, "  deadbeef-1234-uuid \n"))
        val bundle = File(tmp.root, "bundle.zip").apply { writeText("zip") }

        val id = CentralPortalUploader(transport, baseUrl = "https://central.sonatype.com")
            .upload(bundle, "the-user", "the-pass", "my deployment", "USER_MANAGED")

        assertEquals("deadbeef-1234-uuid", id)
        assertEquals("https://central.sonatype.com/api/v1/publisher/upload", transport.uploadUrl)
        val expectedToken = Base64.getEncoder().encodeToString("the-user:the-pass".toByteArray())
        assertEquals("Bearer $expectedToken", transport.authorization)
        assertEquals("my deployment", transport.deploymentName)
        assertEquals("USER_MANAGED", transport.publishingType)
        assertSame(bundle, transport.bundle)
    }

    @Test
    fun upload_throwsOnErrorResponse() {
        val transport = RecordingTransport(CentralPortalResponse(400, "invalid bundle"))
        val bundle = File(tmp.root, "bundle.zip").apply { writeText("zip") }

        val ex = assertThrows(CentralPortalException::class.java) {
            CentralPortalUploader(transport).upload(bundle, "u", "p", null, "USER_MANAGED")
        }
        assertTrue(ex.message!!.contains("400"))
        assertTrue(ex.message!!.contains("invalid bundle"))
    }

    @Test
    fun upload_throwsWhenResponseHasNoDeploymentId() {
        val transport = RecordingTransport(CentralPortalResponse(201, "   "))
        val bundle = File(tmp.root, "bundle.zip").apply { writeText("zip") }

        assertThrows(CentralPortalException::class.java) {
            CentralPortalUploader(transport).upload(bundle, "u", "p", null, "AUTOMATIC")
        }
    }

    @Test
    fun createBundle_excludesMavenMetadata() {
        val repoRoot = File(tmp.root, "repo")
        val dir = artifactDir()
        File(dir, "core-1.0.0.jar").writeText("jar")
        File(dir, "core-1.0.0.pom").writeText("<project/>")
        // publishToMavenLocal writes these at the artifact-id level; Central rejects them.
        val artifactIdDir = dir.parentFile
        File(artifactIdDir, "maven-metadata-local.xml").writeText("<metadata/>")
        File(artifactIdDir, "maven-metadata-local.xml.sha1").writeText("abc")

        val bundle = File(tmp.root, "bundle.zip")
        CentralPortalUploader().createBundle(repoRoot, groupPath, bundle)

        val names = ZipFile(bundle).use { zip -> zip.entries().toList().map { it.name }.toSet() }
        assertTrue(names.any { it.endsWith("core-1.0.0.jar") })
        assertFalse(names.any { it.contains("maven-metadata") })
    }

    @Test
    fun createBundle_omitsChecksumForSignatureFiles() {
        val repoRoot = File(tmp.root, "repo")
        val dir = artifactDir()
        File(dir, "core-1.0.0.jar").writeText("jar")
        File(dir, "core-1.0.0.jar.asc").writeText("sig")

        val bundle = File(tmp.root, "bundle.zip")
        CentralPortalUploader().createBundle(repoRoot, groupPath, bundle)

        val names = ZipFile(bundle).use { zip -> zip.entries().toList().map { it.name }.toSet() }
        assertTrue(names.any { it.endsWith(".jar.asc") })
        assertFalse(names.any { it.endsWith(".asc.md5") || it.endsWith(".asc.sha1") })
    }

    private fun sha1Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-1").digest(bytes).joinToString("") { "%02x".format(it) }
}
