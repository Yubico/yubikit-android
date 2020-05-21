# YubiKit Module
The **YubiKit** module is the core library. It detects the plugged-in YubiKey or one in close proximity to the NFC reader and opens an ISO/IEC 7816 connection to send raw APDU commands to the YubiKey. It also provides a set of utility methods to simplify communication with the YubiKey, methods such as preparing payloads and parsing responses.

## Requirements
The **YubiKit** module requires at minimum Java 7 or Android 4.4. Anything lower than Android 8.0 may have been tested by Yubico to a lesser extent.

## Integrating the YubiKit Module <a name="integration_steps"></a>
### Downloading the Module
#### With Gradle

```gradle
dependencies {
  // core library, connection detection, and raw commands communication with yubikey
  implementation 'com.yubico.yubikit:yubikit:$yubikitVersion'
}
```

And in `gradle.properties` set latest version; for example:
```gradle
yubikitVersion=1.0.0-beta05
```

#### With Maven

```xml
<dependency>
  <groupId>com.yubico.yubikit</groupId>
  <artifactId>yubikit</artifactId>
  <version>1.0.0-beta05</version>
</dependency>
```


### Using the Module Library <a name="using_lib"></a>

**Step 1** Create an instance of `YubikitManager`:
    ```java
   YubiKitManager yubiKitManager = new YubiKitManager(context);
    ```
**Step 2** Create a listener to react to USB session events:
    ```java
    private class UsbListener implements UsbSessionListener {
        @Override
        public void onSessionReceived(@NonNull UsbSession session, Boolean hasPermissions) {
            // yubikey was plugged in
        }

        @Override
        public void onSessionRemoved(@NonNull UsbSession session) {
            // yubikey was unplugged
        }

        @Override
        public void onRequestPermissionsResult(@NonNull UsbSession session, Boolean isGranted) {
            // whether user granted permissions to specific yubikey
        }
    }
    ```
**Step 3** Create a listener to react to NFC session events:
    ```java
    private class NfcListener implements NfcSessionListener {
        void onSessionReceived(@NonNull final NfcSession session) {
            // Tag was discovered
        }
    }
    ```
**Step 4** Subscribe to USB YubiKey session events:
    ```java
    yubiKitManager.startUsbDiscovery(UsbConfiguration(), new UsbListener());
    ```
**Step 5** Subscribe to NFC YubiKey session events:

   **Note**: Discovery over NFC requires an `Activity` in the foreground (we recommend starting discovery over NFC in the `onResume()` method). Discovery over USB does not require an Activity.

    ```java
    @Override
    public void onResume() {
        super.onResume()
        try {
            yubiKitManager.startNfcDiscovery(NfcConfiguration(), activity, new NfcListener);
        } catch (NfcDisabledException e) {
            // show Snackbar message that user needs to turn on NFC for this feature
        } catch (NfcNotFoundException e) {
            // NFC is not available so this feature doesn't work on this device
        }
    }
    ```
**Step 6** Open an ISO/IEC 7816 connection from YubiKey session (`NfcSession` or `UsbSession`), check ATR, create APDU, and then execute it.

   **Note**: The API that sends the APDU commands to the YubiKey is a blocking function. Use a background thread to provide the expected user experience.

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
**Step 7** Stop discovery.

   **Note**: NFC discovery should be stopped before activity goes to background (we recommend stopping discovery over NFC in the `onPause()` method).

    ```java
    @Override
    public void onPause() {
        yubiKitManager.stopNfcDiscovery(activity);
        super.onPause();
    }
    ```

USB discovery can be kept open as long as the `YubiKitManager` instance is alive (we recommend stopping discovery over USB before YubiKitManager is destroyed).

    ```java
    yubiKitManager.stopUsbDiscovery();
    ```
**Step 8** (Optional) For debugging, turn on verbose logging from **YubiKit**.
    ```java
    Logger.setLogger(new Logger() {
        @Override
        protected void logDebug(String message) {
            Log.d(TAG, message);
        }

        @Override
        protected void logError(String message, Throwable throwable) {
            Log.e(TAG, message, throwable);
        }
    });
    ```

### Using the Demo Application <a name="using_demo"></a>
The library comes with a demo application named **YubiKitDemo**.
This demo application showcases what this module, as well as the others, can do.
The source code for the demo application is provided as an example of library
usage.

## Additional Resources <a name="additional_resources"></a>
USB
- [Smart card CCID](https://www.usb.org/sites/default/files/DWG_Smart-Card_CCID_Rev110.pdf)

PIV
- [Interfaces for Personal Identity Verification](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf)
- [Information and examples of what you can do with a PIV-enabled YubiKey](https://developers.yubico.com/PIV/)
