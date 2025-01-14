#!/usr/bin/env python3

import platform
import subprocess

if platform.system() == "Windows":
    gradleExec = "./gradle.bat"
else:
    gradleExec = "./gradlew"

subprocess.run([gradleExec, "spotlessApply"])
