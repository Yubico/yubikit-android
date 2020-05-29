### 1.0.0-beta06
General improvements to YubiKit:
- Various naming changes to classes and methods to better represent what they do.
- Various additional refactorings and minor changes to improve readability and consistency.
- Make the NFC backend extensible so that it can be customized to provide better compatibility.
- Restructure Exception classes to be more consistent.
- OATH module improvements.
- OTP module improvements.
- QR code functionality moved to the demo application.
- FIDO2 module removed.
- 'Smartcard demo' removed.

---

### 1.0.0-beta05
- yubikit: Provides callback to users on whether permissions (for USB plug-in device) from user were accepted or denied.
- yubikit: Provides configurations mechanism for NFC discovery (e.g. play sound, read NDEF tag, etc.).
- otp: Provides API to parse YubiOTP from URI.
- otp: Supports other keyboard layouts for YubiOTP data (static passwords).
- oath: Fixing parsing issues of OATH credentials (for accounts that have empty issuer or contain “/” or “:”).
- piv: Fixing PIV signing (issue with RSA PKCS1.15 padding).
- fido: Allow launching of FIDO intents from fragment as well as from activity.

---

### 1.0.0-beta04
- Added YubiKey configuration capabilities, programming OTP slots.
- HMAC-SHA1 challenge-response.

---

### 1.0.0-beta03
- Making QR/play-services-vision dependency optional for OATH module.

---

### 1.0.0-beta02
- Smart Card functionality based on the Personal Identity Verification (PIV) interface.
- Management API to enable/disable interfaces on YubiKey.

---

### 1.0.0-beta01
- Supports raw APDU communication with YubiKey over NFC and USB.
- Provides high level API for OATH applet.
- Provide FIDO2 wrappers and end-to-end demo.
- Yubico OTP.
