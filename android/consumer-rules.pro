# ============================================================================
# Consumer ProGuard/R8 rules for the yubikit-android module
# These rules are automatically included when a consumer app enables minification.
#
# The pure-Java library modules (core, piv, fido, oath, management, openpgp,
# yubiotp, support) use the java-library Gradle plugin and therefore CANNOT
# ship their own consumerProguardFiles. This file covers them as well.
# ============================================================================

# --- Suppress warnings for classes removed in 3.0 ---
# These classes were deprecated in 2.x and removed in 3.0.0. Users upgrading
# may still have compiled references to them, causing R8 missing-class warnings.

# PIV module (deprecated in 2.4.0)
-dontwarn com.yubico.yubikit.piv.InvalidPinException
-dontwarn com.yubico.yubikit.piv.Padding

# FIDO module (deprecated in 2.x)
-dontwarn com.yubico.yubikit.fido.webauthn.BasicWebAuthnClient
-dontwarn com.yubico.yubikit.fido.client.PinInvalidClientError

# Core module (deprecated in 2.3.0)
-dontwarn com.yubico.yubikit.core.Logger

# Management module (deprecated in 2.5.0) - constructors removed, not the class itself
# No -dontwarn needed for DeviceInfo as the class still exists

# OATH module (deprecated in 2.1.0) - method removed, not the class itself
# No -dontwarn needed for OathSession as the class still exists

# --- Preserve class names for SLF4J Loggers ---
# LoggerFactory.getLogger(ClassName.class) embeds the class name at runtime.
# Without this rule, R8 would rename classes, making log output unreadable.
# -keepnames does NOT prevent tree-shaking: unused classes are still removed.

-keepnames class com.yubico.yubikit.**

# --- ServiceLoader ---
# Base64CodecImpl is loaded reflectively via META-INF/services.
# Modern R8 (AGP 4.2+) automatically detects service files and keeps registered
# implementations, so no explicit -keep rule is needed. The META-INF/services
# file is sufficient to prevent the class from being removed or obfuscated.

# YubiKeyPromptActivity reflectively instantiates YubiKeyPromptAction subclasses
# using getDeclaredConstructor().newInstance().
-keep class * extends com.yubico.yubikit.android.ui.YubiKeyPromptAction {
    public <init>();
}
