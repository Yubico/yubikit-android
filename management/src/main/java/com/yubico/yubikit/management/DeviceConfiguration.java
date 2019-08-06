/*
 * Copyright (C) 2019 Yubico.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.yubico.yubikit.management;

import android.util.SparseArray;

import com.yubico.yubikit.apdu.ApduException;
import com.yubico.yubikit.apdu.Tlv;
import com.yubico.yubikit.apdu.TlvUtils;
import com.yubico.yubikit.apdu.Version;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Class that represents configurations on Yubikey
 */
public final class DeviceConfiguration {

    private static final byte TAG_USB_SUPPORTED = 0x01;
    private static final byte TAG_SERIAL_NUMBER = 0x02;
    private static final byte TAG_USB_ENABLED = 0x03;
    private static final byte TAG_FORMFACTOR = 0x04;
    private static final byte TAG_FIRMWARE_VERSION = 0x05;
    private static final byte TAG_NFC_SUPPORTED = 0x0d;
    private static final byte TAG_NFC_ENABLED = 0x0e;
    private static final byte TAG_CONFIG_LOCKED = 0x0a;

    /**
     * The Configuration Lock is a 16 Byte value that can be set by the user or an administrator/crypto officer.
     * If set, changing any user-configurable device information described in this document will not be allowed.
     * The Configuration Lock has to be supplied when sending the SET DEVICE INFORMATION command.
     * By default, the Configuration Lock is disabled with a default value of 00000000000000000000000000000000 (Byte 00, 16 times).
     */
    private final byte[] configurationLock;

    /**
     * Configurations that actually can be changed by user
     */
    private final int usbSupportedMask;
    private final int nfcSupportedMask;
    private int usbEnabledMask;
    private int nfcEnabledMask;

    /**
     * Configurations that are read-only
     */
    private final Integer serialNumber;
    private final Version firmwareVersion;
    private final FormFactor formFactor;

    /**
     * Helpers to convert tweaked data into byte array
     */
    private final SparseArray<byte[]> initialData;
    private final SparseArray<Tlv> changedData = new SparseArray<>();

    /**
     * Creates instance of {@link DeviceConfiguration}
     * @param data received bytes from read configuration operation
     * @param versionFromSelect version of firmware that was parsed within select operation
     */
    DeviceConfiguration(byte[] data, Version versionFromSelect){
        byte[] configBytes = Arrays.copyOfRange(data, 1, data.length);
        initialData = TlvUtils.parseTlvMap(configBytes);

        configurationLock = initialData.get(TAG_CONFIG_LOCKED);
        byte[] serial = initialData.get(TAG_SERIAL_NUMBER);
        if (serial != null && serial.length >= 4) {
            serialNumber = ByteBuffer.wrap(serial).getInt();
        } else {
            serialNumber = 0;
        }

        byte[] version = initialData.get(TAG_FIRMWARE_VERSION, null);
        if (version != null) {
            firmwareVersion = Version.parse(version);
        } else {
            firmwareVersion = versionFromSelect;
        }

        formFactor = FormFactor.valueOf(initialData.get(TAG_FORMFACTOR));
        usbSupportedMask = getBitMask(initialData.get(TAG_USB_SUPPORTED));
        usbEnabledMask = getBitMask(initialData.get(TAG_USB_ENABLED));
        nfcSupportedMask = getBitMask(initialData.get(TAG_NFC_SUPPORTED));
        nfcEnabledMask = getBitMask(initialData.get(TAG_NFC_ENABLED));
    }

    /**
     * Whether configuration was changed since it received from Yubikey
     * @return true if any configuration was tweaked
     */
    public boolean isChanged() {
        return !getChangedData().isEmpty();
    }

    /**
     * If Configuration Lock is set, changing any user-configurable device information will not be allowed.
     * @return true if set
     */
    public boolean isConfigLocked() {
        for (byte b : configurationLock) {
            if (b != 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * @return serial number of device
     */
    public int getSerial() {
        return serialNumber;
    }

    /**
     * @return firmware version of device
     */
    public Version getFirmwareVersion() {
        return firmwareVersion;
    }

    /**
     * @return key type - value that set during manufacturing
     */
    public FormFactor getFormFactor() {
        return formFactor;
    }

    /**
     * Checks whether that type of application is supported via provided transport
     * @param transportType transport type {@link TransportType}
     * @param applicationType application types {@link ApplicationType}
     * @return true if supported
     */
    public boolean getSupported(TransportType transportType, ApplicationType applicationType) {
        int supportedMask = transportType == TransportType.USB ? usbSupportedMask : nfcSupportedMask;
        return (supportedMask & applicationType.value) == applicationType.value;
    }


    /**
     * Checks whether that type of application is enabled via provided transport
     * @param transportType transport type {@link TransportType}
     * @param applicationType application types {@link ApplicationType}
     * @return true if enabled
     */
    public boolean getEnabled(TransportType transportType, ApplicationType applicationType) {
        int enabledMask = transportType == TransportType.USB ? usbEnabledMask : nfcEnabledMask;
        return (enabledMask & applicationType.value) == applicationType.value;
    }

    /**
     * Sets whether enable/disable that type of application on transport
     * @param transportType transport type {@link TransportType}
     * @param applicationType application types {@link ApplicationType}
     */
    public void setEnabled(TransportType transportType, ApplicationType applicationType, boolean enable) {
        int oldEnabledMask = transportType == TransportType.USB ? usbEnabledMask : nfcEnabledMask;
        int newEnabledMask = enable ? oldEnabledMask | applicationType.value : oldEnabledMask & ~applicationType.value;
        if (oldEnabledMask != newEnabledMask) {
            if (transportType == TransportType.USB) {
                usbEnabledMask = newEnabledMask;
                putMaskValue(TAG_USB_ENABLED, usbEnabledMask);
            } else {
                nfcEnabledMask = newEnabledMask;
                putMaskValue(TAG_NFC_ENABLED, nfcEnabledMask);
            }
        }
    }


    /**
     * Gives a list of tweaked configurations
     * @return list of Tlvs prepared to sent with write configurations operation
     */
    List<Tlv> getChangedData() {
        return asList(changedData);
    }

    /**
     * If updated configuration than reset changed data
     */
    synchronized void dataChanged() {
        for (int i = 0; i < changedData.size(); i++) {
            initialData.put(changedData.keyAt(i), changedData.valueAt(i).getValue());
        }
        changedData.clear();
    }

    /**
     * Helper method to operate with flag updates from user
     * @param tag which tag needs to be changed
     * @param value new value
     */
    private void putMaskValue(byte tag, int value) {
        changedData.put(tag, new Tlv(tag, ByteBuffer.allocate(2).putShort((short) value).array()));
    }

    /**
     * Helper method to read mask value from byte array
     * @param data value of TLV that provides mask
     * @return integer value
     */
    private static int getBitMask(byte[] data) {
        int value = 0;
        if (data == null) {
            return 0;
        }
        for (byte b : data) {
            value <<= 8;
            value += (0xff & b);
        }

        return value;
    }

    /**
     * Helper method that converts sparseArray to list
     * @param sparseArray sparse array of objects
     * @param <T> object withing sparse array
     * @return list of objects
     */
    private static <T> List<T> asList(SparseArray<T> sparseArray) {
        if (sparseArray == null) {
            return null;
        }
        List<T> arrayList = new ArrayList<>(sparseArray.size());
        for (int i = 0; i < sparseArray.size(); i++) {
            arrayList.add(sparseArray.valueAt(i));
        }
        return arrayList;
    }

}
