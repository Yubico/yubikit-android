# PIV Module for YubiKit Android
**PIV** is module of Android YubiKit library provided Yubico.
It provides implementation of Personal Identity Verification (PIV) interface specified in NIST SP 800-73 document "Cryptographic Algorithms and Key Sizes for PIV". 
This enables you to perform RSA or ECC sign/decrypt operations using a private key stored on the smartcard, through common interfaces like PKCS#11.

**PIV** requires at minimum  Java 7 or Android 4.4, future versions may require a later baseline. Anything lower than Android 8.0 may receive less testing by Yubico.

## Integration Steps <a name="integration_steps"></a>
###Download
####Gradle:

```gradle
dependencies {  
  // core library, connection detection, and raw commands communication with YubiKey
  implementation 'com.yubico.yubikit:yubikit:$yubikitVersion'
  // PIV
  implementation 'com.yubico.yubikit:piv:$yubikitVersion'
}
```
And in `gradle.properties` set latest version. Example:
```gradle
yubikitVersion=1.0.0-beta05
```
#### Maven:
```xml
<dependency>
  <groupId>com.yubico.yubikit</groupId>
  <artifactId>yubikit</artifactId>
  <version>1.0.0-beta05</version>
</dependency>

<dependency>
  <groupId>com.yubico.yubikit</groupId>
  <artifactId>piv</artifactId>
  <version>1.0.0-beta05</version>
</dependency>
```
###Using Library <a name="using_lib"></a>

This module requires usage of yubikit core library to detect `YubikeySession` (see [Using YubiKit](../yubikit/README.md))  
And use it to create `PivApplication` to select PIV applet on YubiKey  
```java

    PivApplication application = new PivApplication(session);
    // run provided command/operation (generateKey/putCertificate/sign/etc)
    
```

### Using the Demo Application <a name="using_demo"></a>
Run demo app, select "PIV demo" pivot in navigation drawer. Plug in YubiKey and check what's current certificates you've got. You can generate new key and sign data with that key.
Current demo doesn't allow you to import certificate from file, but it emulated import from pre-defined asset file. And exports to local cache file. Which also can be used to import certificate into another slot.