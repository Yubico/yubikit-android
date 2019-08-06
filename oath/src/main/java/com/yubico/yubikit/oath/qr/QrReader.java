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

package com.yubico.yubikit.oath.qr;

import android.Manifest;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.util.SparseArray;
import android.view.SurfaceHolder;
import android.view.SurfaceView;

import androidx.core.app.ActivityCompat;

import com.google.android.gms.vision.CameraSource;
import com.google.android.gms.vision.Detector;
import com.google.android.gms.vision.barcode.Barcode;
import com.google.android.gms.vision.barcode.BarcodeDetector;
import com.yubico.yubikit.oath.R;
import com.yubico.yubikit.utils.Logger;

import java.io.IOException;

public class QrReader {
    private final Context context;
    private final CameraSource cameraSource;
    private final SurfaceView surfaceView;
    private Callback callback;
    private boolean hasSurface = false;
    private boolean startPreview = false;

    public QrReader(SurfaceView preview) throws NotOperationalBarcode {
        this.context = preview.getContext();
        this.surfaceView = preview;
        preview.getHolder().addCallback(new SurfaceHolder.Callback() {
            @Override
            public void surfaceCreated(SurfaceHolder holder) {
                hasSurface = true;
                if (startPreview) {
                    try {
                        start(callback);
                    } catch (IOException e) {
                        Logger.e(e.getMessage(), e);
                    }
                    startPreview = false;
                }
            }

            @Override
            public void surfaceChanged(SurfaceHolder holder, int format, int width, int height) {

            }

            @Override
            public void surfaceDestroyed(SurfaceHolder holder) {
                hasSurface = false;
            }
        });

        BarcodeDetector barcodeDetector = new BarcodeDetector.Builder(context)
                .setBarcodeFormats(Barcode.QR_CODE).build();
        barcodeDetector.setProcessor(new DetectorProcessor());

        if (!barcodeDetector.isOperational()) {
            // Note: The first time that an app using the barcode or face API is installed on a
            // device, GMS will download a native libraries to the device in order to do detection.
            // Usually this completes before the app is run for the first time.  But if that
            // download has not yet completed, then the above call will not detect any barcodes
            // and/or faces.
            //
            // isOperational() can be used to check if the required native libraries are currently
            // available.  The detectors will automatically become operational once the library
            // downloads complete on device.
            throw new NotOperationalBarcode(context.getString(R.string.yubikit_oath_barcode_not_operational));
        }

        cameraSource = new CameraSource.Builder(context, barcodeDetector)
                .setAutoFocusEnabled(true)
                .build();
    }

    void start(Callback callback) throws IOException {
        this.callback = callback;
        if (ActivityCompat.checkSelfPermission(context, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            return;
        }
        if (hasSurface) {
            cameraSource.start(surfaceView.getHolder());
        } else {
            startPreview = true;
        }
    }

    void stop() {
        cameraSource.stop();
    }

    void release() {
        cameraSource.release();
    }

    public static class NotOperationalBarcode extends Exception {
        public NotOperationalBarcode(String message) {
            super(message);
        }
    }

    private class DetectorProcessor implements Detector.Processor<Barcode> {
        @Override
        public void release() {

        }

        @Override
        public void receiveDetections(Detector.Detections<Barcode> detections) {
            SparseArray<Barcode> barcodes = detections.getDetectedItems();
            for(int i = 0; i < barcodes.size(); i++) {
                int key = barcodes.keyAt(i);
                // get the object by the key.
                if (callback != null) {
                    callback.onBarcodeReceived(barcodes.get(key));
                }
            }
        }
    }
}
