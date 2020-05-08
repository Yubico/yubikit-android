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

package com.yubico.yubikit.demo.oath.qr;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.view.SurfaceView;
import android.view.View;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;

import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.vision.barcode.Barcode;
import com.google.android.material.snackbar.Snackbar;
import com.yubico.yubikit.demo.R;
import com.yubico.yubikit.utils.Logger;

import java.io.IOException;

/**
 * Activity that has camera view that detects QR codes and returns results in intent upon success
 */
public class QrActivity extends AppCompatActivity {

    public final static int GOOGLE_PLAY_SERVICES_UNAVAILABLE = 2;
    public final static int SURFACE_HOLDER_UNAVAILABLE = 3;
    public final static int BARCODE_NOT_OPERATIONAL = 3;

    private final static int PERMISSION_CAMERA = 1;
    private SurfaceView surfaceView;

    private QrReader qrReader;
    private Callback qrReaderCallback = new Callback() {
        @Override
        public void onBarcodeReceived(Barcode barcode) {
            Intent intent = new Intent();
            intent.setData(Uri.parse(barcode.displayValue));
            setResult(RESULT_OK, intent);
            finish();
        }
    };

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_qr_scan);
        surfaceView = findViewById(R.id.surfaceView);
        if (GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(this) == ConnectionResult.SUCCESS) {
            initQrReader();
        } else {
            setResult(GOOGLE_PLAY_SERVICES_UNAVAILABLE);
            finish();
        }

        if (qrReader != null) {
            if (ActivityCompat.checkSelfPermission(getApplicationContext(), Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this, new String[]{Manifest.permission.CAMERA}, PERMISSION_CAMERA);
            }
        }
    }

    @Override
    public void onResume() {
        super.onResume();
        if (qrReader != null) {
            startQrReader();
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (qrReader != null) {
            qrReader.stop();
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (qrReader != null) {
            qrReader.release();
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == PERMISSION_CAMERA) {
            if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                startQrReader();
            } else {
                Snackbar.make(surfaceView, R.string.yubikit_oath_no_permissions, Snackbar.LENGTH_INDEFINITE).setAction(R.string.yubikit_oath_retry, new View.OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        ActivityCompat.requestPermissions(QrActivity.this, new String[]{Manifest.permission.CAMERA}, PERMISSION_CAMERA);
                    }
                }).show();
            }
        }
    }

    private void initQrReader() {
        try {
            qrReader = new QrReader(surfaceView);
        } catch (QrReader.NotOperationalBarcode e) {
            Logger.e(e.getMessage(), e);
            String message = e.getMessage() != null && !e.getMessage().isEmpty() ?
                    e.getMessage() : getString(R.string.yubikit_oath_barcode_not_operational);
            // retry operation might help, because all dynamic barcode recognition libraries get downloaded
            Snackbar.make(surfaceView, message, Snackbar.LENGTH_INDEFINITE).setAction(R.string.yubikit_oath_retry, new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    try {
                        qrReader = new QrReader(surfaceView);
                    } catch (QrReader.NotOperationalBarcode e) {
                        // if second attempt failed we return from activity with error results
                        setResult(BARCODE_NOT_OPERATIONAL);
                        finish();
                    }
                }
            }).show();
        }
    }

    private void startQrReader() {
        try {
            qrReader.start(qrReaderCallback);
        } catch (IOException e) {
            // if the supplied surface holder could not be used as the preview display
            Logger.e(e.getMessage(), e);
            setResult(SURFACE_HOLDER_UNAVAILABLE);
            finish();
        }
    }
}
