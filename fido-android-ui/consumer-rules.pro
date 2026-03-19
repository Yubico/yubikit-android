# ============================================================================
# Consumer ProGuard/R8 rules for the fido-android-ui module
# ============================================================================
# No module-specific rules are needed.
#
# - Public API classes (FidoClient, FidoConfig, FidoConfigManager, Origin,
#   enableFidoWebauthn) are kept by R8 automatically because consumer apps
#   reference them directly in code.
#
# - YubiKitFidoActivity is kept automatically because it is declared in
#   AndroidManifest.xml (AAPT2 generates keep rules for manifest components).
#
# - Class name preservation for SLF4J loggers is handled by the :android
#   module's consumer rule:  -keepnames class com.yubico.yubikit.**
#
# - No reflection, ServiceLoader, or serialization patterns require explicit
#   keep rules.
# ============================================================================
