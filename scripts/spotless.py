#!/usr/bin/env python3

import platform
import subprocess
import sys

if platform.system() == "Windows":
    gradleExec = "./gradlew.bat"
else:
    gradleExec = "./gradlew"

# Get list of staged files (added, copied, modified, renamed)
result = subprocess.run(
    ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
    capture_output=True,
    text=True
)

staged_files = result.stdout.strip().split("\n") if result.stdout.strip() else []

# Filter for files that Spotless can format (Java and Kotlin files)
formattable_files = [f for f in staged_files if f.endswith((".java", ".kt", ".kts"))]

if not formattable_files:
    print("No Java/Kotlin files staged for commit, skipping Spotless.")
    sys.exit(0)

# Use Spotless with ratchetFrom to only format changed files
# This compares against the staged changes (index)
process = subprocess.run(
    [gradleExec, "spotlessApply", "-PspotlessIdeHook=" + ",".join(formattable_files)],
)

if process.returncode != 0:
    sys.exit(process.returncode)

# Re-add the formatted files to the staging area
for f in formattable_files:
    subprocess.run(["git", "add", f])
