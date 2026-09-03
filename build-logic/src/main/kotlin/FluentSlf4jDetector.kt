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

/** A single use of the SLF4J 2.x fluent logging API. */
data class FluentSlf4jUse(val file: File, val line: Int, val text: String) {
    override fun toString() = "${file.path}:$line: ${text.trim()}"
}

/**
 * Finds uses of the SLF4J 2.x fluent logging API (`logger.atDebug()`, `atTrace()`, ...).
 *
 * Those calls are unusable in any code that D8 may desugar. `Logger.atDebug()` and friends are
 * interface *default* methods, and logback-android's prebuilt `ch.qos.logback.classic.Logger`
 * implements none of them. When the consuming app declares `minSdk < 24`, D8 emits the
 * `org/slf4j/Logger$-CC` companion and leaves the call site as `invoke-interface`, but injects no
 * forwarder into the prebuilt class - so dispatch lands on a bogus vtable slot. That surfaces as
 * `AbstractMethodError` on a modern device and as a native SIGSEGV on API 21, which kills the
 * process outright. The device's own API level is irrelevant; only the consumer's `minSdk` matters.
 *
 * The supported shape is an `isXEnabled()` guard around a plain call, which uses no default methods
 * and additionally defers *eagerly* evaluated arguments - something `addArgument(Supplier)` cannot
 * do:
 * ```
 * if (logger.isTraceEnabled()) {
 *   logger.trace("sent: {}", StringUtils.bytesToHex(apdu));
 * }
 * ```
 */
object FluentSlf4jDetector {

    /**
     * Opt-out marker. A file containing this token anywhere is skipped entirely.
     *
     * Reserved for code whose purpose is to demonstrate the defect - `LoggingSmokeTests` has to
     * call the fluent API to show that it still crashes. Production code must not use it; the
     * remedy there is the guard, not a marker.
     */
    const val ALLOW_MARKER = "SLF4J-FLUENT-ALLOWED"

    /** `.atTrace(`, `.atDebug(`, ... including `.atLevel(`, allowing whitespace before the paren. */
    private val FLUENT_CALL = Regex("""\.at(Trace|Debug|Info|Warn|Error|Level)\s*\(""")

    /**
     * Line comments and Javadoc/block-comment bodies. Documenting the banned shape - as this
     * detector's own KDoc does - must not trip the check.
     */
    private val COMMENT_LINE = Regex("""^\s*(//|/\*|\*)""")

    fun scan(file: File): List<FluentSlf4jUse> {
        val lines = file.readLines()
        if (lines.any { it.contains(ALLOW_MARKER) }) {
            return emptyList()
        }
        return lines.mapIndexedNotNull { index, line ->
            if (COMMENT_LINE.containsMatchIn(line) || !FLUENT_CALL.containsMatchIn(line)) {
                null
            } else {
                FluentSlf4jUse(file, index + 1, line)
            }
        }
    }

    fun scan(files: Iterable<File>): List<FluentSlf4jUse> = files.flatMap { scan(it) }

    /** The failure message for [uses], which must not be empty. */
    fun describe(uses: List<FluentSlf4jUse>): String =
        buildString {
            appendLine("Found ${uses.size} use(s) of the SLF4J fluent logging API:")
            uses.forEach { appendLine("  $it") }
            appendLine()
            appendLine("The fluent API breaks whenever the consuming app declares minSdk < 24:")
            appendLine("  AbstractMethodError on a modern device, native SIGSEGV on API 21.")
            appendLine("Use an isXEnabled() guard around a plain call instead:")
            appendLine("  if (logger.isTraceEnabled()) {")
            appendLine("    logger.trace(\"sent: {}\", StringUtils.bytesToHex(apdu));")
            appendLine("  }")
        }
}
