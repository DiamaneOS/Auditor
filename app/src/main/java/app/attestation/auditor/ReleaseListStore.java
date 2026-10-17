package app.attestation.auditor;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import androidx.preference.PreferenceManager;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.security.GeneralSecurityException;

import javax.net.ssl.HttpsURLConnection;

import org.grapheneos.tls.ModernTLSSocketFactory;

// DiamaneOS: caches the signed release list and refreshes it when a boot hash is not on it.
final class ReleaseListStore {
    private static final String TAG = "ReleaseListStore";
    static final String URL = "https://" + RemoteVerifyJob.DOMAIN + "/releases.json";
    private static final String FILE_NAME = "attestation-releases.json";
    private static final String KEY_SEQUENCE = "release_list_sequence";
    private static final int TIMEOUT_MS = 30000;

    private ReleaseListStore() {}

    static synchronized ReleaseList.Release find(final Context context, final TrustConfig trust,
            final TrustConfig.Device device, final Profile2.Evidence evidence)
            throws GeneralSecurityException {
        final ReleaseList cached = cached(context, trust);
        if (cached != null && cached.find(device.id(), evidence.verifiedBootKey(),
                evidence.verifiedBootHash()) != null) {
            return Profile2.match(cached, device, evidence);
        }
        final ReleaseList fresh;
        try {
            fresh = fetch(context, trust);
        } catch (final IOException e) {
            Log.e(TAG, "release list download failed", e);
            throw new GeneralSecurityException("could not download the list of official releases", e);
        }
        return Profile2.match(fresh, device, evidence);
    }

    private static ReleaseList cached(final Context context, final TrustConfig trust) {
        final File file = new File(context.getFilesDir(), FILE_NAME);
        if (!file.exists()) {
            return null;
        }
        try {
            return ReleaseList.parse(Files.readAllBytes(file.toPath()), trust.releaseListSigners);
        } catch (final GeneralSecurityException | IOException e) {
            Log.w(TAG, "ignoring cached release list", e);
            return null;
        }
    }

    private static ReleaseList fetch(final Context context, final TrustConfig trust)
            throws GeneralSecurityException, IOException {
        final HttpsURLConnection connection = (HttpsURLConnection) new URL(URL).openConnection();
        final byte[] envelope;
        try {
            connection.setSSLSocketFactory(new ModernTLSSocketFactory());
            connection.setConnectTimeout(TIMEOUT_MS);
            connection.setReadTimeout(TIMEOUT_MS);
            if (connection.getResponseCode() != 200) {
                throw new IOException("response code: " + connection.getResponseCode());
            }
            try (final InputStream input = connection.getInputStream()) {
                final ByteArrayOutputStream output = new ByteArrayOutputStream();
                final byte[] buffer = new byte[8192];
                for (int read = input.read(buffer); read != -1; read = input.read(buffer)) {
                    if (output.size() + read > ReleaseList.MAX_SIZE) {
                        throw new IOException("release list too large");
                    }
                    output.write(buffer, 0, read);
                }
                envelope = output.toByteArray();
            }
        } finally {
            connection.disconnect();
        }

        final ReleaseList list = ReleaseList.parse(envelope, trust.releaseListSigners);
        final SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(context);
        if (list.sequence < preferences.getLong(KEY_SEQUENCE, 0)) {
            throw new GeneralSecurityException("release list is older than the one already seen");
        }
        final File file = new File(context.getFilesDir(), FILE_NAME);
        final File temporary = new File(context.getFilesDir(), FILE_NAME + ".tmp");
        try (final FileOutputStream output = new FileOutputStream(temporary)) {
            output.write(envelope);
            output.getFD().sync();
        }
        if (!temporary.renameTo(file)) {
            throw new IOException("could not store release list");
        }
        preferences.edit().putLong(KEY_SEQUENCE, list.sequence).apply();
        return list;
    }
}
