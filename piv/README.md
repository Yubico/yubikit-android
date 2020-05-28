# PIV Module
The **PIV** module provides an implementation of the Personal Identity Verification (PIV) interface specified in the NIST SP 800-73 document ["Cryptographic Algorithms and Key Sizes for PIV"](https://csrc.nist.gov/publications/detail/sp/800-78/4/final).
This standard specifies how to perform RSA or ECC sign/decrypt operations using a private key stored on the smart card through common interfaces, such as PKCS#11.

The **PIV** module requires at minimum Java 7 or Android 4.4. Future versions may require a later baseline. Anything lower than Android 8.0 may have been tested to a lesser extent.

## Integrating PIV Module <a name="integration_steps"></a>
### Download
#### Gradle

```gradle
dependencies {  
  // core library, connection detection, and raw APDU commands for communication with YubiKey
  implementation 'com.yubico.yubikit:yubikit:$yubikitVersion'
  // PIV
  implementation 'com.yubico.yubikit:piv:$yubikitVersion'
}
```
And in `gradle.properties` set the latest version; for example:
```gradle
yubikitVersion=1.0.0-beta05
```
#### Maven
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
### Using PIV Library <a name="using_lib"></a>

The **PIV** module requires the YubiKit core library to detect a `YubikeySession` (see the [YubiKit README](../yubikit/README.md)). Use this session to create a `PivApplication` to select the PIV applet on the YubiKey.  
```java

    PivApplication application = new PivApplication(session);
    // run provided command/operation (generateKey/putCertificate/sign/etc)

```

### Using Demo Application <a name="using_demo"></a>
1. Run the [demo app](./YubikitDemo).
2. Select "PIV demo" in the navigation drawer.
3. Plug in the YubiKey or use its NFC connection and check the current certificates. You can generate a new key and sign data with that key.

**Note**: The current demo does not allow import of certificates from file. Instead, it emulates import from pre-defined asset file and exports to local cache file. Use the cache file to import a certificate into another slot.

## Additional Resources <a name="additional_resources"></a>
* [Read more about PIV on the developer site](http://developers.yubico.com/PIV/)
