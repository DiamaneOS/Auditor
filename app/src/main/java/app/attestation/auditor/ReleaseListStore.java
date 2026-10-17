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
import java.security.PublicKey;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

import org.grapheneos.tls.ModernTLSSocketFactory;

// DiamaneOS: downloads the signed release list for every check that needs it. The stored copy is
// used only while offline and only for a limited time, so withdrawn builds stop passing.
final class ReleaseListStore {
    private static final String TAG = "ReleaseListStore";
    static final String URL = "https://" + RemoteVerifyJob.DOMAIN + "/releases.json";
    static final long MAX_OFFLINE_AGE_MS = 7L * 24 * 60 * 60 * 1000;
    private static final String FILE_NAME = "attestation-releases.json";
    private static final String KEY_SEQUENCE = "release_list_sequence";
    private static final String KEY_FETCHED = "release_list_fetched";
    private static final int TIMEOUT_MS = 30000;

    interface Network {
        byte[] get() throws IOException;
    }

    interface Storage {
        byte[] list() throws IOException;
        long fetched();
        long sequence();
        void store(byte[] list, long sequence, long fetched) throws IOException;
    }

    private ReleaseListStore() {}

    static synchronized ReleaseList.Release find(final Context context, final TrustConfig trust,
            final TrustConfig.Device device, final Profile2.Evidence evidence)
            throws GeneralSecurityException {
        return Profile2.match(load(ReleaseListStore::download, new PreferenceStorage(context),
                trust.releaseListSigners, System.currentTimeMillis()), device, evidence);
    }

    static ReleaseList load(final Network network, final Storage storage,
            final Map<String, PublicKey> signers, final long now) throws GeneralSecurityException {
        final byte[] fetched;
        try {
            fetched = network.get();
        } catch (final IOException e) {
            Log.w(TAG, "release list download failed", e);
            return offline(storage, signers, now, e);
        }
        final ReleaseList list = ReleaseList.parse(fetched, signers);
        if (list.sequence < storage.sequence()) {
            throw new GeneralSecurityException("release list is older than the one already seen");
        }
        try {
            storage.store(fetched, list.sequence, now);
        } catch (final IOException e) {
            Log.w(TAG, "could not store release list", e);
        }
        return list;
    }

    private static ReleaseList offline(final Storage storage, final Map<String, PublicKey> signers,
            final long now, final IOException cause) throws GeneralSecurityException {
        final long age = now - storage.fetched();
        byte[] cached = null;
        try {
            cached = storage.list();
        } catch (final IOException e) {
            Log.w(TAG, "could not read stored release list", e);
        }
        if (cached == null || age < 0 || age > MAX_OFFLINE_AGE_MS) {
            throw new GeneralSecurityException("could not download the list of official releases", cause);
        }
        final ReleaseList list = ReleaseList.parse(cached, signers);
        if (list.sequence < storage.sequence()) {
            throw new GeneralSecurityException("stored release list is older than the one already seen");
        }
        return list;
    }

    private static byte[] download() throws IOException {
        final HttpsURLConnection connection = (HttpsURLConnection) new URL(URL).openConnection();
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
                return output.toByteArray();
            }
        } finally {
            connection.disconnect();
        }
    }

    private record PreferenceStorage(Context context) implements Storage {
        private SharedPreferences preferences() {
            return PreferenceManager.getDefaultSharedPreferences(context);
        }

        private File file() {
            return new File(context.getFilesDir(), FILE_NAME);
        }

        @Override
        public byte[] list() throws IOException {
            return file().exists() ? Files.readAllBytes(file().toPath()) : null;
        }

        @Override
        public long fetched() {
            return preferences().getLong(KEY_FETCHED, 0);
        }

        @Override
        public long sequence() {
            return preferences().getLong(KEY_SEQUENCE, 0);
        }

        @Override
        public void store(final byte[] list, final long sequence, final long fetched) throws IOException {
            final File temporary = new File(context.getFilesDir(), FILE_NAME + ".tmp");
            try (final FileOutputStream output = new FileOutputStream(temporary)) {
                output.write(list);
                output.getFD().sync();
            }
            if (!temporary.renameTo(file())) {
                throw new IOException("could not store release list");
            }
            preferences().edit().putLong(KEY_SEQUENCE, sequence).putLong(KEY_FETCHED, fetched).apply();
        }
    }
}
