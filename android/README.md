# YubiKit Android Module
The **android** module implements the basic classes needed to interact with
YubiKeys on Android. It detects the plugged-in YubiKey or one in close
proximity to the NFC reader and opens an ISO/IEC 7816 connection to send raw
APDU commands to the YubiKey.

## Requirements
The **YubiKit** module requires at minimum Java 7 or Android 4.4. Anything
lower than Android 8.0 may have been tested to a lesser extent.

## Integrating YubiKit Module <a name="integration_steps"></a>
### Downloading
#### Gradle

```gradle
dependencies {
  // connection detection, and raw commands communication with yubikey
  implementation 'com.yubico.yubikit:android:$yubikitVersion'
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
```


### Using YubiKit Library <a name="using_lib"></a>

**Step 1** Create an instance of `YubikitManager`:
```java
   YubiKitManager yubiKitManager = new YubiKitManager(context);
```

**Step 2** Create a listener to react to USB device events:
```java
    private class UsbListener implements UsbDeviceListener {
        @Override
        public void onDeviceAttached(UsbYubiKeyDevice device, boolean hasPermissions) {
            // YubiKey was plugged in
        }

        @Override
        public void onDeviceRemoved(UsbYubiKeyDevice device) {
            // YubiKey was unplugged
        }

        @Override
        public void onRequestPermissionsResult(UsbYubiKeyDevice device, boolean isGranted) {
            // whether user granted permissions to specific YubiKey
        }
    }
```
**Step 3** Create a listener to react to NFC device events:
```java
    private class NfcListener implements NfcDeviceListener {
        void onDeviceAttached(NfcYubiKeyDevice device) {
            // Tag was discovered
        }
    }
```
**Step 4** Subscribe to USB YubiKey device events:
```java
    yubiKitManager.startUsbDiscovery(UsbConfiguration(), new UsbListener());
```
**Step 5** Subscribe to NFC YubiKey device events.

**Note**: Discovery over NFC requires an `Activity` in the foreground (we recommend starting discovery over NFC in the `onResume()` method). Discovery over USB does not require an Activity.

```java
    @Override
    public void onResume() {
        super.onResume()
        try {
            yubiKitManager.startNfcDiscovery(new NfcConfiguration(), activity, new NfcListener());
        } catch (NfcNotAvailableException e) {
            if (e.disabled) {
                // show Snackbar message that user needs to turn on NFC for this feature
            } else {
                // NFC is not available so this feature does not work on this device
            }
        }
    }
```
**Step 6** Open an ISO/IEC 7816 connection from YubiKey device (`NfcYubiKeyDevice` or `UsbYubiKeyDevice`), create APDU, and then execute it.

**Note**: The API that sends the APDU commands to the YubiKey is a blocking function. Use a background thread to provide the expected user experience.

```java
    executorService.execute(() -> {
        //connect to the YubiKey / start the connection
        try(SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
            // here you can run your command set.
            // Example:
            SmartCardProtocol protocol = new SmartCardProtocol(connection);
            byte[] aid = new byte[] {0xA0, 0x00, 0x00, 0x03, 0x08};
            protocol.select(aid);  // Select a smartcard application
            protocol.sendAndReceive(new Apdu(0x00, 0xA4, 0x00, 0x00)));
        } catch (ApplicationNotFoundException | IOException e) {
            // handle error that occurred during communication with key
        }
    });
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

### Using Demo Application <a name="using_demo"></a>
The library comes with a demo application, the [**YubiKitDemo**](../YubikitDemo).
This demo application showcases what this module can do as well as what the other
modules can do.
The source code for the demo application is provided as an example of library
usage.

## Additional Resources <a name="additional_resources"></a>
USB
- [Smart card CCID](https://www.usb.org/sites/default/files/DWG_Smart-Card_CCID_Rev110.pdf)

PIV
- [Interfaces for Personal Identity Verification](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf)
- [Information and examples of what you can do with a PIV-enabled YubiKey](https://developers.yubico.com/PIV/)
