# SSH Manager - Android App

WebView wrapper for the SSH Manager web UI.

## Prerequisites
- Android Studio (latest stable)
- Android SDK 34+
- JDK 17

## Setup

1. Open this `android/` directory in Android Studio
2. Edit `app/build.gradle` and set your server URL:
   ```
   buildConfigField "String", "SERVER_URL", "\"https://YOUR_SERVER_IP:8443\""
   ```
3. (Optional) For certificate pinning, get your cert fingerprint:
   ```
   openssl x509 -in /path/to/cert.pem -noout -fingerprint -sha256
   ```
   Set the `CERT_FINGERPRINT` constant in `MainActivity.java` (remove colons, lowercase).

## Build

- **Debug**: Run > Run 'app' (or `./gradlew assembleDebug`)
- **Release**: Build > Generate Signed Bundle/APK

## PWA Alternative

No Android Studio? Use the web app as a PWA:

1. Open `https://YOUR_SERVER_IP:8443` in Chrome on Android
2. Accept the self-signed certificate warning
3. Tap the menu (three dots) > "Add to Home screen"
4. The app will run in standalone mode with the dark theme
