package app.attestation.auditor;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.hash.Hashing;
import com.google.common.io.BaseEncoding;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.regex.Pattern;

import app.attestation.auditor.attestation.ParsedAttestationRecord;

// DiamaneOS: devices without a manufacturer-rooted attestation chain (trust profile 2) and the
// keys trusted for them. Kept as data so device specifics stay out of the verification code.
final class TrustConfig {
    static final String FORMAT = "diamaneos-attestation-trust";
    private static final Pattern SHA256_HEX = Pattern.compile("[0-9A-F]{64}");

    record Device(String id, String name, String osName, String verifiedBootKey, int securityLevel) {}

    final String auditorReleaseSigner;
    final ImmutableMap<String, PublicKey> releaseListSigners;
    final ImmutableList<Device> devices;

    private TrustConfig(final String auditorReleaseSigner,
            final ImmutableMap<String, PublicKey> releaseListSigners,
            final ImmutableList<Device> devices) {
        this.auditorReleaseSigner = auditorReleaseSigner;
        this.releaseListSigners = releaseListSigners;
        this.devices = devices;
    }

    static TrustConfig parse(final String json) throws GeneralSecurityException {
        try {
            final JSONObject root = new JSONObject(json);
            if (!FORMAT.equals(root.getString("format")) || root.getInt("version") != 1) {
                throw new GeneralSecurityException("unsupported trust configuration");
            }
            final String signer = root.getString("auditorReleaseSigner");
            if (!signer.isEmpty() && !SHA256_HEX.matcher(signer).matches()) {
                throw new GeneralSecurityException("invalid Auditor signer digest");
            }

            final ImmutableMap.Builder<String, PublicKey> signers = ImmutableMap.builder();
            final JSONArray signerArray = root.getJSONArray("releaseListSigners");
            for (int i = 0; i < signerArray.length(); i++) {
                final PublicKey key = decodeP256(signerArray.getString(i));
                signers.put(keyId(key), key);
            }

            final ImmutableList.Builder<Device> devices = ImmutableList.builder();
            final JSONArray deviceArray = root.getJSONArray("devices");
            for (int i = 0; i < deviceArray.length(); i++) {
                final JSONObject device = deviceArray.getJSONObject(i);
                final String verifiedBootKey = device.getString("verifiedBootKey");
                if (!SHA256_HEX.matcher(verifiedBootKey).matches()) {
                    throw new GeneralSecurityException("invalid verified boot key");
                }
                devices.add(new Device(device.getString("id"), device.getString("name"),
                        device.getString("osName"), verifiedBootKey,
                        securityLevel(device.getString("securityLevel"))));
            }
            return new TrustConfig(signer, signers.buildOrThrow(), devices.build());
        } catch (final JSONException | IllegalArgumentException e) {
            throw new GeneralSecurityException("invalid trust configuration", e);
        }
    }

    List<Device> devicesFor(final String verifiedBootKey, final int securityLevel) {
        return devices.stream()
                .filter(d -> d.verifiedBootKey.equals(verifiedBootKey) && d.securityLevel == securityLevel)
                .collect(ImmutableList.toImmutableList());
    }

    static String keyId(final PublicKey key) {
        return BaseEncoding.base16().encode(Hashing.sha256().hashBytes(key.getEncoded()).asBytes());
    }

    private static PublicKey decodeP256(final String base64) throws GeneralSecurityException {
        final PublicKey key = KeyFactory.getInstance("EC")
                .generatePublic(new X509EncodedKeySpec(BaseEncoding.base64().decode(base64)));
        final AlgorithmParameters p256 = AlgorithmParameters.getInstance("EC");
        p256.init(new ECGenParameterSpec("secp256r1"));
        final ECParameterSpec expected = p256.getParameterSpec(ECParameterSpec.class);
        if (!(key instanceof ECPublicKey ec)
                || !ec.getParams().getCurve().equals(expected.getCurve())
                || !ec.getParams().getOrder().equals(expected.getOrder())) {
            throw new GeneralSecurityException("release list signer must be a P-256 key");
        }
        return key;
    }

    private static int securityLevel(final String name) throws GeneralSecurityException {
        return switch (name) {
            case "TRUSTED_ENVIRONMENT" -> ParsedAttestationRecord.securityLevelToInt(
                    ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT);
            case "STRONG_BOX" -> ParsedAttestationRecord.securityLevelToInt(
                    ParsedAttestationRecord.SecurityLevel.STRONG_BOX);
            default -> throw new GeneralSecurityException("invalid security level: " + name);
        };
    }
}
