# PIV Module
The **PIV** module provides an implementation of the Personal Identity Verification (PIV) interface specified in the [NIST SP 800-73 document "Cryptographic Algorithms and Key Sizes for PIV"](https://csrc.nist.gov/publications/detail/sp/800-73/4/final). 
This standard specifies how to perform RSA or ECC sign/decrypt operations using a private key stored on the smartcard, through common interfaces, such as PKCS#11.

The **PIV** module requires at minimum Java 7 or Android 4.4. Future versions may require a later baseline. Anything lower than Android 8.0 may receive less testing by Yubico.

## Integration Steps <a name="integration_steps"></a>
### Download
#### Gradle:

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
### Using Library <a name="using_lib"></a>

The **PIV** module requires the yubikit core library to detect a `YubikeySession` (see [Using YubiKit](../yubikit/README.md)). Use this session to create a `PivApplication` to select the PIV applet on YubiKey.  
```java

    PivApplication application = new PivApplication(session);
    // run provided command/operation (generateKey/putCertificate/sign/etc)
    
```

### Using the Demo Application <a name="using_demo"></a>
1. Run demo app
1. Select "PIV demo" pivot in navigation drawer
1. Plug in YubiKey and check the current certificates. You can generate new key and sign data with that key.

Note: The current demo doesn't allow import of certificates from file. Instead, it emulates import from pre-defined asset file and exports to local cache file. Use the cache file to import a certificate into another slot.

## Additional Resources <a name="additional_resources"></a>
* [Read more about PIV on the developer site](http://developers.yubico.com/PIV/)
