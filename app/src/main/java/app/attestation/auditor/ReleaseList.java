package app.attestation.auditor;

import com.google.common.collect.ImmutableList;
import com.google.common.io.BaseEncoding;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Map;
import java.util.regex.Pattern;

// DiamaneOS: signed list of the values each official release reports through attestation. The
// release pipeline publishes it, so trust profile 2 needs no app update per OS release.
final class ReleaseList {
    static final String FORMAT = "diamaneos-attestation-releases";
    static final String PAYLOAD_FORMAT = "diamaneos-attestation-releases-payload";
    static final int MAX_SIZE = 1024 * 1024;
    // the payload nests five levels, and deeper input could exhaust the parser's stack
    private static final int MAX_DEPTH = 8;
    private static final String ALGORITHM = "ECDSA_P256_SHA256";
    private static final Pattern SHA256_HEX = Pattern.compile("[0-9A-F]{64}");

    record Release(String build, String verifiedBootHash, int osVersion, int osPatchLevel,
            int vendorPatchLevel, int bootPatchLevel, int attestationVersion, int keyMintVersion) {}

    record DeviceReleases(String id, String verifiedBootKey, ImmutableList<Release> releases) {}

    final long sequence;
    final ImmutableList<DeviceReleases> devices;

    private ReleaseList(final long sequence, final ImmutableList<DeviceReleases> devices) {
        this.sequence = sequence;
        this.devices = devices;
    }

    // Returns the release with this boot hash for the device, or null.
    Release find(final String deviceId, final String verifiedBootKey, final String verifiedBootHash) {
        for (final DeviceReleases device : devices) {
            if (device.id.equals(deviceId) && device.verifiedBootKey.equals(verifiedBootKey)) {
                for (final Release release : device.releases) {
                    if (release.verifiedBootHash.equals(verifiedBootHash)) {
                        return release;
                    }
                }
            }
        }
        return null;
    }

    static ReleaseList parse(final byte[] envelope, final Map<String, PublicKey> signers)
            throws GeneralSecurityException {
        if (envelope.length > MAX_SIZE) {
            throw new GeneralSecurityException("release list too large");
        }
        try {
            checkDepth(envelope);
            final JSONObject root = new JSONObject(new String(envelope, StandardCharsets.UTF_8));
            if (!FORMAT.equals(root.getString("format")) || root.getInt("version") != 1) {
                throw new GeneralSecurityException("unsupported release list");
            }
            final byte[] payload = BaseEncoding.base64().decode(root.getString("payload"));
            verifySignature(payload, root.getJSONArray("signatures"), signers);
            checkDepth(payload);
            return parsePayload(new JSONObject(new String(payload, StandardCharsets.UTF_8)));
        } catch (final JSONException | IllegalArgumentException e) {
            throw new GeneralSecurityException("invalid release list", e);
        }
    }

    static void checkDepth(final byte[] json) throws GeneralSecurityException {
        int depth = 0;
        boolean inString = false;
        boolean escaped = false;
        for (final byte b : json) {
            if (inString) {
                if (escaped) {
                    escaped = false;
                } else if (b == '\\') {
                    escaped = true;
                } else if (b == '"') {
                    inString = false;
                }
            } else if (b == '"') {
                inString = true;
            } else if (b == '{' || b == '[') {
                if (++depth > MAX_DEPTH) {
                    throw new GeneralSecurityException("release list nested too deeply");
                }
            } else if (b == '}' || b == ']') {
                depth--;
            }
        }
    }

    private static void verifySignature(final byte[] payload, final JSONArray signatures,
            final Map<String, PublicKey> signers) throws GeneralSecurityException, JSONException {
        for (int i = 0; i < signatures.length(); i++) {
            final JSONObject entry = signatures.getJSONObject(i);
            final PublicKey key = signers.get(entry.getString("keyId"));
            if (key == null || !ALGORITHM.equals(entry.getString("algorithm"))) {
                continue;
            }
            final Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initVerify(key);
            signature.update(payload);
            if (signature.verify(BaseEncoding.base64().decode(entry.getString("signature")))) {
                return;
            }
        }
        throw new GeneralSecurityException("release list has no valid trusted signature");
    }

    private static ReleaseList parsePayload(final JSONObject payload)
            throws GeneralSecurityException, JSONException {
        if (!PAYLOAD_FORMAT.equals(payload.getString("format")) || payload.getInt("version") != 1) {
            throw new GeneralSecurityException("unsupported release list payload");
        }
        final long sequence = payload.getLong("sequence");
        if (sequence < 1) {
            throw new GeneralSecurityException("invalid release list sequence");
        }
        final ImmutableList.Builder<DeviceReleases> devices = ImmutableList.builder();
        final JSONArray deviceArray = payload.getJSONArray("devices");
        for (int i = 0; i < deviceArray.length(); i++) {
            final JSONObject device = deviceArray.getJSONObject(i);
            final ImmutableList.Builder<Release> releases = ImmutableList.builder();
            final JSONArray releaseArray = device.getJSONArray("releases");
            for (int j = 0; j < releaseArray.length(); j++) {
                final JSONObject r = releaseArray.getJSONObject(j);
                releases.add(new Release(r.getString("build"), sha256Hex(r, "verifiedBootHash"),
                        positive(r, "osVersion"), positive(r, "osPatchLevel"),
                        positive(r, "vendorPatchLevel"), positive(r, "bootPatchLevel"),
                        positive(r, "attestationVersion"), positive(r, "keyMintVersion")));
            }
            devices.add(new DeviceReleases(device.getString("id"),
                    sha256Hex(device, "verifiedBootKey"), releases.build()));
        }
        return new ReleaseList(sequence, devices.build());
    }

    private static String sha256Hex(final JSONObject object, final String name)
            throws GeneralSecurityException, JSONException {
        final String value = object.getString(name);
        if (!SHA256_HEX.matcher(value).matches()) {
            throw new GeneralSecurityException("invalid " + name);
        }
        return value;
    }

    private static int positive(final JSONObject object, final String name)
            throws GeneralSecurityException, JSONException {
        final int value = object.getInt(name);
        if (value <= 0) {
            throw new GeneralSecurityException("invalid " + name);
        }
        return value;
    }
}
