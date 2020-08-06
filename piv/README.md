# PIV Module
The **PIV** module provides an implementation of the Personal Identity
Verification (PIV) interface specified in the NIST SP 800-73 document
["Cryptographic Algorithms and Key Sizes for PIV"](https://csrc.nist.gov/publications/detail/sp/800-78/4/final).
This standard specifies how to perform RSA or ECC sign/decrypt operations using
a private key stored on the YubiKey.

## Integrating PIV Module <a name="integration_steps"></a>
### Download
#### Gradle

```gradle
dependencies {
  implementation 'com.yubico.yubikit:android:$yubikitVersion'
  implementation 'com.yubico.yubikit:piv:$yubikitVersion'
}
```
And in `gradle.properties` set the latest version; for example:
```gradle
yubikitVersion=2.0.0
```
#### Maven
```xml
<dependency>
  <groupId>com.yubico.yubikit</groupId>
  <artifactId>android</artifactId>
  <version>2.0.0</version>
</dependency>

<dependency>
  <groupId>com.yubico.yubikit</groupId>
  <artifactId>piv</artifactId>
  <version>2.0.0</version>
</dependency>
```
### Using PIV Library <a name="using_lib"></a>
The **PIV** module requires the YubiKit android module to detect a
`YubikeySession` (see [Android Module README](../android/README.md)).

```java
    PivApplication application = new PivApplication(session);
    // run provided command/operation (generateKey/putCertificate/sign/etc)

```

### Using Demo Application <a name="using_demo"></a>
1. Run the [demo app](../YubikitDemo).
2. Select "PIV" in the navigation drawer.
3. Plug in the YubiKey or use its NFC connection and check the current certificates. You can generate a new key and sign data with that key.

## Additional Resources <a name="additional_resources"></a>
* [Read more about PIV on the developer site](http://developers.yubico.com/PIV/)
