# This ProGuard configuration uses minimal rules — the goal is to rely on the
# consumer-rules.pro files provided by the :android and :fido-android-ui modules
# to verify that those are set up correctly.

# This file is only used when building the release version of AndroidDemo:
# ./gradlew :AndroidDemo:assembleRelease

# For correct building of the app in release mode, the following env vars need to be set:
# YKDEMO_STORE_FILE, YKDEMO_STORE_PASSWORD, YKDEMO_KEY_ALIAS, YKDEMO_KEY_PASSWORD

# The following rules are here to support app-specific protections.


# BouncyCastle JCA provider: The demo app registers BouncyCastleProvider via
# Security.addProvider() in MainActivity. BouncyCastle's Provider.Service entries
# reference algorithm implementation classes by name strings, which R8 cannot
# trace. Without these rules, R8 strips the implementation classes, causing
# TLS handshake failures (ERR_CERT_AUTHORITY_INVALID) in WebView and any other
# component that performs SSL connections through the JCA framework.
-keep class org.bouncycastle.jcajce.provider.** { *; }
-keep class org.bouncycastle.jce.provider.** { *; }

# BouncyCastle references javax.naming classes which are not available on Android.
-dontwarn javax.naming.**