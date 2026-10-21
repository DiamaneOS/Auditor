package app.attestation.auditor;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import com.google.common.collect.ImmutableList;
import com.google.common.io.BaseEncoding;

import org.bouncycastle.asn1.ASN1Primitive;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import app.attestation.auditor.attestation.AuthorizationList;
import app.attestation.auditor.attestation.ParsedAttestationRecord;
import app.attestation.auditor.attestation.RootOfTrust;

import static app.attestation.auditor.AttestationProtocol.EC_CURVE;
import static app.attestation.auditor.AttestationProtocol.KEY_DIGEST;
import static app.attestation.auditor.AttestationProtocol.TAG;
import static app.attestation.auditor.AttestationProtocol.generateKeyPair;
import static app.attestation.auditor.AttestationProtocol.generateRandomToken;
import static app.attestation.auditor.AttestationProtocol.getCertificateChain;
import static app.attestation.auditor.AttestationProtocol.getKeyBuilder;
import static app.attestation.auditor.AttestationProtocol.readRawResource;

// DiamaneOS: trust profile 2, for devices whose secure hardware gives no manufacturer-rooted
// chain. The first pairing is trusted on the user's confirmation and must match an official
// release exactly. Later checks are pinned to it like any other pairing.
final class Profile2 {
    static final String KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17";
    private static final String KEY_USAGE_OID = "2.5.29.15";
    private static final String ECDSA_SHA256_OID = "1.2.840.10045.4.3.2";
    // fresh key, pairing attest key, local root attest key without attestation data
    static final int CHAIN_LENGTH = 3;
    static final long LOCAL_CHALLENGE_LIFETIME_MS = 2 * 60 * 1000;

    record Evidence(String verifiedBootKey, String verifiedBootHash, boolean deviceLocked,
            RootOfTrust.VerifiedBootState verifiedBootState, int securityLevel, int osVersion,
            int osPatchLevel, int vendorPatchLevel, int bootPatchLevel, int attestationVersion,
            int keyMintVersion) {}

    interface ReleaseLookup {
        // Returns the matching release or throws, refreshing the list once if needed.
        ReleaseList.Release find(TrustConfig.Device device, Evidence evidence)
                throws GeneralSecurityException;
    }

    private Profile2() {}

    static void checkChainShape(final Certificate[] chain) throws GeneralSecurityException {
        if (chain.length != CHAIN_LENGTH
                || ((X509Certificate) chain[CHAIN_LENGTH - 1]).getExtensionValue(KEY_DESCRIPTION_OID) != null) {
            throw new GeneralSecurityException("root certificate is not a valid key attestation root");
        }
    }

    // Called from AttestationProtocol.verifyStateless when the chain has no manufacturer root.
    static TrustConfig.Device device(final TrustConfig trust, final boolean releaseAuditor,
            final ParsedAttestationRecord attestation, final RootOfTrust rootOfTrust,
            final String verifiedBootKey) throws GeneralSecurityException {
        if (!releaseAuditor) {
            throw new GeneralSecurityException("pairing without a manufacturer root requires the DiamaneOS Auditor");
        }
        return device(trust, evidence(attestation, rootOfTrust, verifiedBootKey));
    }

    // Called from AttestationProtocol.verifyStateless once the attest key is known. Returns the
    // review flags of a first pairing, and nothing for a manufacturer-rooted chain (no device).
    static List<String> verify(final TrustConfig.Device device, final boolean attestKey,
            final boolean hasPersistentKey, final ParsedAttestationRecord attestation,
            final RootOfTrust rootOfTrust, final String verifiedBootKey,
            final Certificate[] certificates, final ReleaseLookup releases, final long challengeAgeMs)
            throws GeneralSecurityException {
        List<String> reviewFlags = List.of();
        if (device != null) {
            if (!attestKey) {
                throw new GeneralSecurityException("missing pairing attest key");
            }
            final Evidence evidence = evidence(attestation, rootOfTrust, verifiedBootKey);
            releases.find(device, evidence);
            if (!hasPersistentKey) {
                checkFreshness(challengeAgeMs, LOCAL_CHALLENGE_LIFETIME_MS);
                reviewFlags = reviewFlags(certificates);
            }
        }
        return reviewFlags;
    }

    static Evidence evidence(final ParsedAttestationRecord attestation,
            final RootOfTrust rootOfTrust, final String verifiedBootKey) {
        final AuthorizationList teeEnforced = attestation.teeEnforced;
        return new Evidence(verifiedBootKey,
                BaseEncoding.base16().encode(rootOfTrust.verifiedBootHash.orElse(new byte[0])),
                rootOfTrust.deviceLocked, rootOfTrust.verifiedBootState,
                ParsedAttestationRecord.securityLevelToInt(attestation.attestationSecurityLevel),
                teeEnforced.osVersion.orElse(0), teeEnforced.osPatchLevel.orElse(0),
                teeEnforced.vendorPatchLevel.orElse(0), teeEnforced.bootPatchLevel.orElse(0),
                attestation.attestationVersion, attestation.keymasterVersion);
    }

    static TrustConfig.Device device(final TrustConfig config, final Evidence evidence)
            throws GeneralSecurityException {
        if (!evidence.deviceLocked) {
            throw new GeneralSecurityException("device is not locked");
        }
        if (evidence.verifiedBootState != RootOfTrust.VerifiedBootState.SELF_SIGNED) {
            throw new GeneralSecurityException("verified boot state is not self signed");
        }
        final List<TrustConfig.Device> devices =
                config.devicesFor(evidence.verifiedBootKey, evidence.securityLevel);
        if (devices.isEmpty()) {
            throw new GeneralSecurityException("invalid verified boot key fingerprint: " + evidence.verifiedBootKey);
        }
        return devices.get(0);
    }

    // Every reported value must equal the official release with this boot hash.
    static ReleaseList.Release match(final ReleaseList list, final TrustConfig.Device device,
            final Evidence evidence) throws GeneralSecurityException {
        final ReleaseList.Release release = list == null ? null
                : list.find(device.id(), evidence.verifiedBootKey, evidence.verifiedBootHash);
        if (release == null) {
            throw new GeneralSecurityException("verified boot hash is not an official release: "
                    + evidence.verifiedBootHash);
        }
        if (release.osVersion() != evidence.osVersion
                || release.osPatchLevel() != evidence.osPatchLevel
                || release.vendorPatchLevel() != evidence.vendorPatchLevel
                || release.bootPatchLevel() != evidence.bootPatchLevel
                || release.attestationVersion() != evidence.attestationVersion
                || release.keyMintVersion() != evidence.keyMintVersion) {
            throw new GeneralSecurityException("reported versions do not match official release "
                    + release.build());
        }
        return release;
    }

    static void checkFreshness(final long challengeAgeMs, final long lifetimeMs)
            throws GeneralSecurityException {
        if (challengeAgeMs < 0 || challengeAgeMs > lifetimeMs) {
            throw new GeneralSecurityException("challenge expired");
        }
    }

    // Plausibility checks against how Android Keystore encodes these certificates. They only
    // flag a pairing for review and never reject it.
    static ImmutableList<String> reviewFlags(final Certificate[] chain) {
        final ImmutableList.Builder<String> flags = ImmutableList.builder();
        try {
            final X509Certificate leaf = (X509Certificate) chain[0];
            final X509Certificate attestKey = (X509Certificate) chain[1];
            final X509Certificate root = (X509Certificate) chain[2];
            for (final X509Certificate c : new X509Certificate[]{leaf, attestKey, root}) {
                if (c.getVersion() != 3 || !ECDSA_SHA256_OID.equals(c.getSigAlgOID())) {
                    flags.add("certificate-format");
                    break;
                }
            }
            if (!Arrays.equals(leaf.getIssuerX500Principal().getEncoded(),
                    attestKey.getSubjectX500Principal().getEncoded())
                    || !Arrays.equals(attestKey.getIssuerX500Principal().getEncoded(),
                    root.getSubjectX500Principal().getEncoded())
                    || !Arrays.equals(root.getIssuerX500Principal().getEncoded(),
                    root.getSubjectX500Principal().getEncoded())) {
                flags.add("issuer-names");
            }
            if (!leaf.getNotBefore().equals(attestKey.getNotBefore())
                    || !leaf.getNotAfter().equals(attestKey.getNotAfter())
                    || !attestKey.getNotBefore().equals(root.getNotBefore())
                    || !attestKey.getNotAfter().equals(root.getNotAfter())) {
                flags.add("validity");
            }
            if (!extensions(leaf).equals(Set.of(KEY_DESCRIPTION_OID, KEY_USAGE_OID))
                    || !extensions(attestKey).equals(Set.of(KEY_DESCRIPTION_OID, KEY_USAGE_OID))
                    || !keyUsage(leaf, 0) || keyUsage(leaf, 5) || !keyUsage(attestKey, 5)) {
                flags.add("extensions");
            }
            if (!isDer(leaf) || !isDer(attestKey)) {
                flags.add("attestation-encoding");
            }
        } catch (final ClassCastException | IOException | CertificateParsingException e) {
            flags.add("certificate-format");
        }
        return flags.build();
    }

    private static Set<String> extensions(final X509Certificate certificate) {
        final java.util.HashSet<String> oids = new java.util.HashSet<>();
        if (certificate.getCriticalExtensionOIDs() != null) {
            oids.addAll(certificate.getCriticalExtensionOIDs());
        }
        if (certificate.getNonCriticalExtensionOIDs() != null) {
            oids.addAll(certificate.getNonCriticalExtensionOIDs());
        }
        return oids;
    }

    private static boolean keyUsage(final X509Certificate certificate, final int bit) {
        final boolean[] usage = certificate.getKeyUsage();
        return usage != null && usage.length > bit && usage[bit];
    }

    // The attestation extension must be canonical DER, as KeyMint produces it.
    private static boolean isDer(final X509Certificate certificate)
            throws IOException, CertificateParsingException {
        final byte[] wrapped = certificate.getExtensionValue(KEY_DESCRIPTION_OID);
        if (wrapped == null) {
            throw new CertificateParsingException("missing key description");
        }
        final byte[] octets = org.bouncycastle.asn1.ASN1OctetString.getInstance(wrapped).getOctets();
        return Arrays.equals(octets, ASN1Primitive.fromByteArray(octets).getEncoded("DER"));
    }

    // DiamaneOS: without attestation keys (profile 2), a local root attest key without a
    // challenge has no attestation data and only signs the pairing attest key below it.
    static void generateLocalRootAttestKeys(final String rootAlias, final String attestAlias,
            final byte[] challenge, final boolean useStrongBox) throws GeneralSecurityException, IOException {
        final KeyGenParameterSpec.Builder root = new KeyGenParameterSpec.Builder(rootAlias,
                KeyProperties.PURPOSE_ATTEST_KEY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec(EC_CURVE))
                .setDigests(KEY_DIGEST);
        if (useStrongBox) {
            root.setIsStrongBoxBacked(true);
        }
        generateKeyPair(root.build());
        generateKeyPair(getKeyBuilder(attestAlias, KeyProperties.PURPOSE_ATTEST_KEY,
                useStrongBox, challenge, false).setAttestKeyAlias(rootAlias).build());
    }

    // Only devices listed for trust profile 2 fall back, so a temporary lack of attestation keys
    // elsewhere keeps its original error.
    static boolean useLocalRootAttestKey(final Context context, final Throwable e)
            throws GeneralSecurityException {
        return isAttestationKeysUnavailable(e) && TrustConfig.get(context).hasBuildDevice(Build.DEVICE);
    }

    private static boolean isAttestationKeysUnavailable(final Throwable e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof android.security.KeyStoreException k && k.getNumericErrorCode()
                    == android.security.KeyStoreException.ERROR_ATTESTATION_KEYS_UNAVAILABLE) {
                return true;
            }
        }
        return false;
    }

    // DiamaneOS: whether this device's attestation chains up to a manufacturer root. Remote
    // enrollment asks the user to confirm the setup before a first pairing without one.
    static boolean hasManufacturerRootedAttestation(final Context context) {
        final String alias = "probe_attestation_key";
        try {
            final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            final boolean strongBox = context.getPackageManager()
                    .hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
            try {
                generateKeyPair(getKeyBuilder(alias, KeyProperties.PURPOSE_SIGN, strongBox,
                        generateRandomToken(), true).build());
                final Certificate[] chain = getCertificateChain(keyStore, alias);
                final byte[] root = chain[chain.length - 1].getEncoded();
                for (final int id : new int[]{R.raw.google_root_0, R.raw.google_root_1,
                        R.raw.google_root_2, R.raw.google_root_3, R.raw.google_root_4}) {
                    if (Arrays.equals(root, readRawResource(context, id))) {
                        return true;
                    }
                }
                return false;
            } finally {
                keyStore.deleteEntry(alias);
            }
        } catch (final GeneralSecurityException | IOException e) {
            Log.w(TAG, "attestation probe failed", e);
            return false;
        }
    }

    static String hex(final byte[] bytes) {
        return BaseEncoding.base16().encode(bytes);
    }
}
