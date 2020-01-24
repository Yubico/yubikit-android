# YubiKit Module of Android YubiKit
**YubiKit** module is core libraryy, providing the functionality to detect whether the YubiKey is plugged in or tapped over NFC, and to open the ISO/IEC 7816 connection that enables sending raw APDU commands to the key. 
It also provides a set of utility methods to allow easy communication with device, prepare payloads and parse responses.

The **YubiKit** requires at minimum  Java 7 or Android 4.4, future versions may require a later baseline. Anything lower than Android 8.0 may receive less testing by Yubico.

## Integration Steps <a name="integration_steps"></a>
###Download
####Gradle:

```gradle
dependencies {  
  // core library, connection detection, and raw commands communication with yubikey
  implementation 'com.yubico.yubikit:yubikit:$yubikitVersion'
}
```
And in `gradle.properties` set latest version. Example:
```gradle
yubikitVersion=1.0.0-beta04
```
#### Maven:
```xml
<dependency>
  <groupId>com.yubico.yubikit</groupId>
  <artifactId>yubikit</artifactId>
  <version>1.0.0-beta04</version>
</dependency>
```
###Using Library <a name="using_lib"></a>

- 1. Create instance of `YubikitManager`
```java
    YubiKitManager yubiKitManager = new YubiKitManager(context);
```
- 2. Create listener for any successful or failed key discovery
```java
    private class UsbListener implements UsbSessionListener {
        @Override
        public void onSessionReceived(@NonNull UsbSession session) {
            // yubikey was plugged in
        }

        @Override
        public void onSessionRemoved(@NonNull UsbSession session) {
            // yubikey was unplugged
        }

        @Override
        public void onError(@NonNull UsbSession session, @NonNull Throwable error) {
            // user didn't grant permissions to specific yubikey
        }
    }
```
for NFC session discoveries

```java
    private class NfcListener implements NfcSessionListener {
        void onSessionReceived(@NonNull final NfcSession session) {
            // Tag was discovered
        }
    }
```
-3. Start discovery for key over USB or NFC. Note: discovery over NFC requires `Activity` that is in foreground (we recommend starting discovery over NFC in `onResume()`). Discovery over USB does not require Activity.
```java
    yubiKitManager.startUsbDiscovery(true, new UsbListener());
```
and/or
```java
    @Override
    public void onResume() {
        super.onResume()
        try {
            yubiKitManager.startNfcDiscovery(false, activity, new NfcListener);
        } catch (NfcDisabledException e) {
            // show Snackbar message that user needs to turn on NFC for this feature
        } catch (NfcNotFoundException e) {
            // NFC is not available so this feature doesn't work on this device
        }
    }
```
-4. Open ISO/IEC 7816 connection from YubiKey session (NfcSession or UsbSession), check ATR, create APDU and execute it. Note: the API that send APDU commands to YubiKey are blocking and require background thread to be created in order to provide good user experience.
```java
    executorService.execute {
        try {
            //connect to the key / start the connection
            Iso7816Connection connection = session.openIso7816Connection();

            // here you can run your command set.
            // Example:            
            // connection.getAtr();
            // byte[] aid = StringUtils.byteArrayOfInts(new int[] {0xA0, 0x00, 0x00, 0x03, 0x08});
            // connection.execute(new Apdu(0x00, 0xA4, 0x04, 0x00, aid)));
        } catch (IOException e) {
            // handle error that occured during communication with key
        } finally {
            try {
                connection.close();
            } catch (IOException ignore) {
            }
        }
    }
```
-5. Stop discovery. Note: for NFC it should be done before activity goes to background (we recommend stopping discovery over NFC in `onPause()`). 
```java
    @Override
    public void onPause() {
        yubiKitManager.stopNfcDiscovery(activity);
        super.onPause();
    }
```
Discovery over USB can be kept as long as `YubiKitManager` instance is alive (we recommend stopping discovery over USB before yubiKitManager is destroyed).
```java
    yubiKitManager.stopUsbDiscovery(activity)
```
-6. Optional. Turn on verbose logging from **YubiKit** for debugging purposes:
```java
        Logger.getInstance().setLogger(new ILogger() {
            @Override
            void logDebug(message: String?) {
                Log.d(TAG, message);
            }
            @Override
            void logError(message: String?, throwable: Throwable?) {
                Log.e(TAG, message, throwable);
            }
        })
```

### Using the Demo Application <a name="using_demo"></a>
The library comes with a demo application named **YubikitDemo**. The application is implemented in Kotlin.  
Run the application and select Demo Smartcard pivot in navigation drawer to see how to read certificate from YubiKey slot using raw APDU command.  
Plug in YubiKey and tap "Run demo" button or tap YubiKey over NFC reader

Raw commands demo shows how to read a certificate from the YubiKey slot 9c, using the raw command interface from YubiKit.

Notes:

1. The key should be connected to the device before clicking the "Run demo" button (for NFC connection clicking "Run demo" button is not required) 
2. This code requires a certificate to be added to the key on slot 9c.
3. The certificate to test with is provided in keystore/cert.der
    
To load certificate to the key you can use ykman tool. Run: 
```
yubico-piv-tool -s9c -icert.der -KDER -averify -aimport-cert
```

or you can upload the certificate using the [YubiKey Manager](https://www.yubico.com/products/services-software/download/yubikey-manager/).

## Additional Resources <a name="additional_resources"></a>
USB - [Smart card CCID](https://www.usb.org/sites/default/files/DWG_Smart-Card_CCID_Rev110.pdf)  
PIV - [Interfaces for Personal Identity Verification](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf)  
PIV - [Information and examples of what you can do with a PIV enabled YubiKey](https://developers.yubico.com/PIV/)  

