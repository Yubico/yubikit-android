#!/usr/bin/env python3

import os
import platform
import subprocess
import sys

if platform.system() == "Windows":
    gradleExec = "./gradlew.bat"
else:
    gradleExec = "./gradlew"

# Get the repository root directory
repo_root = subprocess.run(
    ["git", "rev-parse", "--show-toplevel"],
    capture_output=True, text=True
).stdout.strip()

# Get list of staged files (added, copied, modified, renamed)
result = subprocess.run(
    ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
    capture_output=True, text=True
)
staged_files = result.stdout.strip().split("\n") if result.stdout.strip() else []

# Filter for files that Spotless can format (Java and Kotlin files)
formattable_files = [f for f in staged_files if f.endswith((".java", ".kt", ".kts"))]

if not formattable_files:
    sys.exit(0)

# Convert to absolute paths (required by spotlessIdeHook)
absolute_files = [os.path.join(repo_root, f) for f in formattable_files]

# Use Spotless to format only the staged files
process = subprocess.run(
    [gradleExec, "spotlessApply", "--quiet",
     "-PspotlessIdeHook=" + ",".join(absolute_files)],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)

if process.returncode != 0:
    print("Spotless formatting failed.", file=sys.stderr)
    sys.exit(process.returncode)

