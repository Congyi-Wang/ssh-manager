package com.sshmanager.app;

import android.annotation.SuppressLint;
import android.net.http.SslError;
import android.os.Bundle;
import android.webkit.SslErrorHandler;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import androidx.appcompat.app.AppCompatActivity;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;

public class MainActivity extends AppCompatActivity {

    private WebView webView;

    // SHA-256 fingerprint of your server's self-signed certificate.
    // Generate with: openssl x509 -in cert.pem -noout -fingerprint -sha256
    // Replace colons with empty string and lowercase it.
    // Set to null to accept any cert from your server (less secure but easier for dev).
    private static final String CERT_FINGERPRINT = null;

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        webView = findViewById(R.id.webview);
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setCacheMode(WebSettings.LOAD_DEFAULT);
        settings.setDatabaseEnabled(true);

        webView.setWebChromeClient(new WebChromeClient());

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
                if (CERT_FINGERPRINT == null) {
                    // Accept any cert from the server (dev mode)
                    handler.proceed();
                    return;
                }

                // Pin to specific certificate fingerprint
                try {
                    X509Certificate cert = error.getCertificate().getX509Certificate();
                    if (cert != null) {
                        MessageDigest md = MessageDigest.getInstance("SHA-256");
                        byte[] digest = md.digest(cert.getEncoded());
                        StringBuilder sb = new StringBuilder();
                        for (byte b : digest) {
                            sb.append(String.format("%02x", b));
                        }
                        if (sb.toString().equals(CERT_FINGERPRINT)) {
                            handler.proceed();
                            return;
                        }
                    }
                } catch (Exception e) {
                    // Fall through to cancel
                }
                handler.cancel();
            }
        });

        webView.loadUrl(BuildConfig.SERVER_URL);
    }

    @Override
    public void onBackPressed() {
        if (webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }
}
