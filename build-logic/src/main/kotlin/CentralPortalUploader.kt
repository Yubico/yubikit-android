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

import java.io.DataOutputStream
import java.io.File
import java.net.HttpURLConnection
import java.net.URI
import java.net.URLEncoder
import java.security.MessageDigest
import java.util.Base64
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Uploads already-signed Maven artifacts to the Sonatype Central Publisher Portal.
 *
 * The Scribe signing step produces a directory in Maven repository layout containing the
 * artifacts (jar/aar/pom/module + sources/javadoc) alongside their GPG `.asc` signatures. This
 * uploader zips that tree into a deployment "bundle" (generating the md5/sha1 checksums that the
 * portal requires and that `publishToMavenLocal` does not emit) and POSTs it to the portal's
 * bundle-upload API. Because the whole tree is uploaded verbatim, the `.asc` signatures are
 * preserved — unlike the `maven-publish` plugin, which ignores externally produced signatures.
 *
 * See https://central.sonatype.org/publish/publish-portal-api/
 */
class CentralPortalUploader(
    private val transport: CentralPortalTransport = HttpUrlConnectionTransport(),
    private val baseUrl: String = "https://central.sonatype.com",
) {

    /**
     * Zips the artifacts under [groupPath] (relative to [repoRoot], e.g. `com/yubico/yubikit`) into
     * [bundleFile], preserving the Maven repository layout. Every regular file is added verbatim
     * (including `.asc` signatures); missing md5/sha1 checksums are generated for each artifact.
     *
     * @return [bundleFile]
     */
    fun createBundle(repoRoot: File, groupPath: String, bundleFile: File): File {
        val groupDir = repoRoot.resolve(groupPath)
        require(groupDir.isDirectory) {
            "No artifacts found to publish at ${groupDir.absolutePath}"
        }

        val files = groupDir.walkTopDown().filter { it.isFile }.sortedBy { it.invariantPath() }.toList()
        require(files.isNotEmpty()) { "No files found to publish under ${groupDir.absolutePath}" }
        val existing = files.mapTo(HashSet()) { it.invariantPath() }

        bundleFile.parentFile?.mkdirs()
        ZipOutputStream(bundleFile.outputStream().buffered()).use { zip ->
            for (file in files) {
                val entryPath = file.relativeTo(repoRoot).invariantSeparatorsPath
                zip.writeEntry(entryPath, file.readBytes())

                if (file.isChecksumOrSignature()) continue
                for ((suffix, algorithm) in CHECKSUM_ALGORITHMS) {
                    val checksum = File("${file.path}.$suffix")
                    if (checksum.invariantPath() in existing) continue
                    val hex = file.digestHex(algorithm)
                    zip.writeEntry("$entryPath.$suffix", hex.toByteArray(Charsets.US_ASCII))
                }
            }
        }
        return bundleFile
    }

    /**
     * Uploads [bundle] to the Central Portal upload endpoint using a Bearer token derived from
     * [username]/[password] (`base64("user:pass")`).
     *
     * @param publishingType `USER_MANAGED` (validate, then publish manually) or `AUTOMATIC`.
     * @return the deployment id returned by the portal.
     * @throws CentralPortalException if the portal responds with a non-2xx status.
     */
    fun upload(
        bundle: File,
        username: String,
        password: String,
        deploymentName: String?,
        publishingType: String,
    ): String {
        val token = Base64.getEncoder().encodeToString("$username:$password".toByteArray(Charsets.UTF_8))
        val response = transport.uploadBundle(
            uploadUrl = "$baseUrl/api/v1/publisher/upload",
            authorization = "Bearer $token",
            deploymentName = deploymentName,
            publishingType = publishingType,
            bundle = bundle,
        )
        if (response.code !in 200..299) {
            throw CentralPortalException(
                "Central Portal upload failed: HTTP ${response.code}. Body: ${response.body}"
            )
        }
        val deploymentId = response.body.trim()
        if (deploymentId.isEmpty()) {
            throw CentralPortalException("Central Portal upload succeeded but returned no deployment id")
        }
        return deploymentId
    }

    private companion object {
        // Maven's "SHA-1"/"MD5" digest names mapped to the checksum file suffixes Central expects.
        val CHECKSUM_ALGORITHMS = listOf("md5" to "MD5", "sha1" to "SHA-1")
    }
}

/** Thrown when the Central Portal rejects a request. */
class CentralPortalException(message: String) : RuntimeException(message)

/** Response from a Central Portal request. */
data class CentralPortalResponse(val code: Int, val body: String)

/** Seam over the HTTP interaction so the upload logic can be unit-tested without a network. */
interface CentralPortalTransport {
    fun uploadBundle(
        uploadUrl: String,
        authorization: String,
        deploymentName: String?,
        publishingType: String,
        bundle: File,
    ): CentralPortalResponse
}

/** Default [CentralPortalTransport] that performs a real multipart/form-data POST. */
class HttpUrlConnectionTransport : CentralPortalTransport {
    override fun uploadBundle(
        uploadUrl: String,
        authorization: String,
        deploymentName: String?,
        publishingType: String,
        bundle: File,
    ): CentralPortalResponse {
        val query = buildString {
            append("?publishingType=").append(URLEncoder.encode(publishingType, "UTF-8"))
            if (!deploymentName.isNullOrBlank()) {
                append("&name=").append(URLEncoder.encode(deploymentName, "UTF-8"))
            }
        }
        val url = URI(uploadUrl + query).toURL()
        val boundary = "----YubiKitCentralPortal${bundle.length()}"
        val connection = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            setRequestProperty("Authorization", authorization)
            setRequestProperty("Content-Type", "multipart/form-data; boundary=$boundary")
        }

        DataOutputStream(connection.outputStream).use { out ->
            out.writeBytes("--$boundary\r\n")
            out.writeBytes(
                "Content-Disposition: form-data; name=\"bundle\"; filename=\"${bundle.name}\"\r\n"
            )
            out.writeBytes("Content-Type: application/octet-stream\r\n\r\n")
            bundle.inputStream().buffered().use { it.copyTo(out) }
            out.writeBytes("\r\n--$boundary--\r\n")
        }

        val code = connection.responseCode
        val stream = if (code in 200..299) connection.inputStream else connection.errorStream
        val body = stream?.bufferedReader()?.use { it.readText() } ?: ""
        return CentralPortalResponse(code, body)
    }
}

private fun File.invariantPath(): String = path.replace(File.separatorChar, '/')

private fun File.isChecksumOrSignature(): Boolean =
    name.endsWith(".asc") || name.endsWith(".md5") || name.endsWith(".sha1")

private fun File.digestHex(algorithm: String): String {
    val digest = MessageDigest.getInstance(algorithm)
    inputStream().buffered().use { input ->
        val buffer = ByteArray(8192)
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            digest.update(buffer, 0, read)
        }
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}

private fun ZipOutputStream.writeEntry(path: String, bytes: ByteArray) {
    putNextEntry(ZipEntry(path))
    write(bytes)
    closeEntry()
}
