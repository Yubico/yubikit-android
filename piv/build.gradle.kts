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
    id("yubikit-library")
}

dependencies {
    api(project(":core"))
}

tasks.test {
    systemProperty("org.slf4j.simpleLogger.defaultLogLevel", "trace")
}

description = "This library provides implementation of Personal Identity Verification (PIV) interface specified in NIST SP 800-73 document \"Cryptographic Algorithms and Key Sizes for PIV\". This enables you to perform RSA or ECC sign/decrypt operations using a private key stored on the YubiKey."
