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
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class FluentSlf4jDetectorTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private fun javaFile(name: String, body: String): File =
        tmp.newFile(name).apply { writeText(body.trimIndent()) }

    @Test
    fun `flags each fluent level`() {
        val file =
            javaFile(
                "Levels.java",
                """
                class Levels {
                  void m() {
                    logger.atTrace().log("a");
                    logger.atDebug().log("b");
                    logger.atInfo().log("c");
                    logger.atWarn().log("d");
                    logger.atError().log("e");
                    logger.atLevel(Level.DEBUG).log("f");
                  }
                }
                """,
            )

        val uses = FluentSlf4jDetector.scan(file)

        assertEquals(6, uses.size)
        assertEquals(listOf(3, 4, 5, 6, 7, 8), uses.map { it.line })
    }

    @Test
    fun `flags a chain broken across lines`() {
        val file =
            javaFile(
                "Chain.java",
                """
                class Chain {
                  void m() {
                    logger
                        .atTrace()
                        .setMessage("sent: {}")
                        .addArgument(() -> hex(apdu))
                        .log();
                  }
                }
                """,
            )

        val uses = FluentSlf4jDetector.scan(file)

        assertEquals(1, uses.size)
        assertEquals(4, uses.single().line)
    }

    @Test
    fun `allows the guarded plain call`() {
        val file =
            javaFile(
                "Guarded.java",
                """
                class Guarded {
                  void m() {
                    if (logger.isTraceEnabled()) {
                      logger.trace("sent: {}", hex(apdu));
                    }
                    logger.debug("alg: {}", alg);
                  }
                }
                """,
            )

        assertEquals(emptyList<FluentSlf4jUse>(), FluentSlf4jDetector.scan(file))
    }

    @Test
    fun `ignores comments that document the banned shape`() {
        val file =
            javaFile(
                "Documented.java",
                """
                /**
                 * Do not write logger.atDebug().log("x") here.
                 * <p>Use the guard instead.
                 */
                class Documented {
                  // logger.atTrace().log("old code");
                  /* logger.atWarn().log("also old"); */
                  void m() {}
                }
                """,
            )

        assertEquals(emptyList<FluentSlf4jUse>(), FluentSlf4jDetector.scan(file))
    }

    @Test
    fun `does not flag unrelated methods starting with at`() {
        val file =
            javaFile(
                "Unrelated.java",
                """
                class Unrelated {
                  void m() {
                    list.get(0).attach(x);
                    buffer.atomicRead();
                    logger.debug("at debug time: {}", x);
                  }
                }
                """,
            )

        assertEquals(emptyList<FluentSlf4jUse>(), FluentSlf4jDetector.scan(file))
    }

    @Test
    fun `honours the opt-out marker for a file that demonstrates the defect`() {
        val file =
            javaFile(
                "Repro.java",
                """
                /** ${FluentSlf4jDetector.ALLOW_MARKER} - demonstrates the crash on purpose. */
                class Repro {
                  void m() {
                    logger.atDebug().log("this must not be flagged");
                  }
                }
                """,
            )

        assertEquals(emptyList<FluentSlf4jUse>(), FluentSlf4jDetector.scan(file))
    }

    @Test
    fun `marker in one file does not exempt another`() {
        val exempt =
            javaFile(
                "Exempt.java",
                "/** ${FluentSlf4jDetector.ALLOW_MARKER} */ class E { void m() " +
                    "{ logger.atDebug().log(\"e\"); } }",
            )
        val other = javaFile("Other.java", "class O { void m() { logger.atWarn().log(\"o\"); } }")

        val uses = FluentSlf4jDetector.scan(listOf(exempt, other))

        assertEquals(1, uses.size)
        assertEquals(other, uses.single().file)
    }

    @Test
    fun `scans multiple files and reports every use`() {
        val a = javaFile("A.java", "class A { void m() { logger.atDebug().log(\"a\"); } }")
        val b = javaFile("B.java", "class B { void m() { logger.trace(\"b\"); } }")

        val uses = FluentSlf4jDetector.scan(listOf(a, b))

        assertEquals(1, uses.size)
        assertEquals(a, uses.single().file)
    }

    @Test
    fun `describe names every offending site and the remedy`() {
        val file = javaFile("C.java", "class C { void m() { logger.atDebug().log(\"c\"); } }")

        val message = FluentSlf4jDetector.describe(FluentSlf4jDetector.scan(file))

        assertTrue(message, message.contains("C.java:1"))
        assertTrue(message, message.contains("isTraceEnabled"))
        assertTrue(message, message.contains("minSdk < 24"))
    }
}
