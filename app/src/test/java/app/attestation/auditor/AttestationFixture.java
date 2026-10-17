package app.attestation.auditor;

import com.google.common.hash.Hashing;
import com.google.common.io.BaseEncoding;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import app.attestation.auditor.attestation.AttestationApplicationId;
import app.attestation.auditor.attestation.AuthorizationList;
import app.attestation.auditor.attestation.ParsedAttestationRecord;
import app.attestation.auditor.attestation.RootOfTrust;

// Software-made chains shaped like a profile 2 Auditee's. They carry no hardware trust.
final class AttestationFixture {
    static final byte[] AVB_KEY = sha256("test AVB key");
    static final byte[] AUDITOR_SIGNER = sha256("test Auditor signer");
    static final KeyPair LIST_SIGNER = keyPair();

    final KeyPair root = keyPair();
    final KeyPair attest = keyPair();
    KeyPair leaf = keyPair();

    byte[] challenge = sha256("challenge");
    byte[] attestChallenge;
    byte[] bootKey = AVB_KEY;
    byte[] bootHash = sha256("release 1");
    boolean locked = true;
    RootOfTrust.VerifiedBootState state = RootOfTrust.VerifiedBootState.SELF_SIGNED;
    ParsedAttestationRecord.SecurityLevel level = ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT;
    int osVersion = 170000;
    int osPatchLevel = 202610;
    int vendorPatchLevel = 20261005;
    int bootPatchLevel = 20261005;
    int attestationVersion = 300;
    int keyMintVersion = 300;
    String packageName = "de.diamaneos.auditor";
    long appVersion = 9202;
    byte[] signer = AUDITOR_SIGNER;
    boolean rootExtension;

    Certificate[] chain() throws Exception {
        final byte[] attestKeyChallenge = attestChallenge != null ? attestChallenge : challenge;
        final X500Name rootName = new X500Name("CN=Android Keystore Key");
        final Certificate rootCert = certificate(root.getPublic().getEncoded(), rootName, rootName, root,
                rootExtension ? extension(Set.of(AuthorizationList.OperationPurpose.ATTEST_KEY),
                        attestKeyChallenge) : null, KeyUsage.keyCertSign);
        final Certificate attestCert = certificate(attest.getPublic().getEncoded(), rootName, rootName, root,
                extension(Set.of(AuthorizationList.OperationPurpose.ATTEST_KEY), attestKeyChallenge),
                KeyUsage.keyCertSign);
        final Certificate leafCert = certificate(leaf.getPublic().getEncoded(), rootName, rootName, attest,
                extension(Set.of(AuthorizationList.OperationPurpose.SIGN,
                        AuthorizationList.OperationPurpose.VERIFY), challenge), KeyUsage.digitalSignature);
        return new Certificate[]{leafCert, attestCert, rootCert};
    }

    private DERSequence extension(final Set<AuthorizationList.OperationPurpose> purposes,
            final byte[] keyChallenge) {
        final AuthorizationList tee = AuthorizationList.builder()
                .setPurpose(purposes)
                .setAlgorithm(AuthorizationList.Algorithm.EC)
                .setKeySize(256)
                .setEcCurve(AuthorizationList.EcCurve.P_256)
                .setDigest(Set.of(AuthorizationList.DigestMode.SHA_2_256))
                .setOrigin(AuthorizationList.KeyOrigin.GENERATED)
                .setRootOfTrust(RootOfTrust.create(bootKey, locked, state, Optional.of(bootHash)))
                .setOsVersion(osVersion)
                .setOsPatchLevel(osPatchLevel)
                .setVendorPatchLevel(vendorPatchLevel)
                .setBootPatchLevel(bootPatchLevel)
                .build();
        final AuthorizationList software = AuthorizationList.builder()
                .setAttestationApplicationId(new AttestationApplicationId(
                        List.of(new AttestationApplicationId.AttestationPackageInfo(packageName, appVersion)),
                        List.of(signer)))
                .build();
        return (DERSequence) new DERSequence(ParsedAttestationRecord.create(attestationVersion, level,
                keyMintVersion, level, keyChallenge, new byte[0], software, tee, leaf.getPublic())
                .toAsn1Sequence().toArray());
    }

    private static Certificate certificate(final byte[] spki, final X500Name issuer, final X500Name subject,
            final KeyPair signerKey, final DERSequence keyDescription, final int keyUsage) throws Exception {
        final AlgorithmIdentifier ecdsa = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10045.4.3.2"));
        final V3TBSCertificateGenerator generator = new V3TBSCertificateGenerator();
        generator.setSerialNumber(new ASN1Integer(1));
        generator.setSignature(ecdsa);
        generator.setIssuer(issuer);
        generator.setSubject(subject);
        generator.setStartDate(new Time(new Date(0)));
        generator.setEndDate(new Time(new Date(2461449600000L)));
        generator.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(spki));
        final java.util.ArrayList<Extension> extensions = new java.util.ArrayList<>();
        extensions.add(new Extension(Extension.keyUsage, true, new KeyUsage(keyUsage).getEncoded()));
        if (keyDescription != null) {
            extensions.add(new Extension(new ASN1ObjectIdentifier(Profile2.KEY_DESCRIPTION_OID), false,
                    new DEROctetString(keyDescription.getEncoded())));
        }
        generator.setExtensions(new Extensions(extensions.toArray(new Extension[0])));
        final TBSCertificate tbs = generator.generateTBSCertificate();
        final Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(signerKey.getPrivate());
        signature.update(tbs.getEncoded("DER"));
        final byte[] der = new DERSequence(new org.bouncycastle.asn1.ASN1Encodable[]{
                tbs, ecdsa, new DERBitString(signature.sign())}).getEncoded("DER");
        return CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
    }

    String bootHashHex() {
        return BaseEncoding.base16().encode(bootHash);
    }

    static TrustConfig trust() throws Exception {
        return TrustConfig.parse(new JSONObject()
                .put("format", TrustConfig.FORMAT)
                .put("version", 1)
                .put("auditorReleaseSigner", BaseEncoding.base16().encode(AUDITOR_SIGNER))
                .put("releaseListSigners", new JSONArray().put(
                        Base64.getEncoder().encodeToString(LIST_SIGNER.getPublic().getEncoded())))
                .put("devices", new JSONArray().put(new JSONObject()
                        .put("id", "FP6")
                        .put("name", "Fairphone 6")
                        .put("osName", "DiamaneOS")
                        .put("verifiedBootKey", BaseEncoding.base16().encode(AVB_KEY))
                        .put("securityLevel", "TRUSTED_ENVIRONMENT")))
                .toString());
    }

    static JSONObject release(final byte[] bootHash, final int osPatchLevel) throws Exception {
        return new JSONObject()
                .put("build", "2026101700")
                .put("verifiedBootHash", BaseEncoding.base16().encode(bootHash))
                .put("osVersion", 170000)
                .put("osPatchLevel", osPatchLevel)
                .put("vendorPatchLevel", 20261005)
                .put("bootPatchLevel", 20261005)
                .put("attestationVersion", 300)
                .put("keyMintVersion", 300);
    }

    static byte[] releaseList(final KeyPair signerKey, final long sequence, final JSONObject... releases)
            throws Exception {
        final JSONArray array = new JSONArray();
        for (final JSONObject release : releases) {
            array.put(release);
        }
        final byte[] payload = new JSONObject()
                .put("format", ReleaseList.PAYLOAD_FORMAT)
                .put("version", 1)
                .put("sequence", sequence)
                .put("issued", "2026-10-17T00:00:00Z")
                .put("devices", new JSONArray().put(new JSONObject()
                        .put("id", "FP6")
                        .put("verifiedBootKey", BaseEncoding.base16().encode(AVB_KEY))
                        .put("releases", array)))
                .toString().getBytes(StandardCharsets.UTF_8);
        final Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(signerKey.getPrivate());
        signature.update(payload);
        return envelope(payload, TrustConfig.keyId(signerKey.getPublic()), signature.sign());
    }

    static byte[] envelope(final byte[] payload, final String keyId, final byte[] signature) throws Exception {
        return new JSONObject()
                .put("format", ReleaseList.FORMAT)
                .put("version", 1)
                .put("payload", Base64.getEncoder().encodeToString(payload))
                .put("signatures", new JSONArray().put(new JSONObject()
                        .put("keyId", keyId)
                        .put("algorithm", "ECDSA_P256_SHA256")
                        .put("signature", Base64.getEncoder().encodeToString(signature))))
                .toString().getBytes(StandardCharsets.UTF_8);
    }

    static KeyPair keyPair() {
        try {
            final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return generator.generateKeyPair();
        } catch (final Exception e) {
            throw new AssertionError(e);
        }
    }

    static byte[] sha256(final String value) {
        return Hashing.sha256().hashString(value, StandardCharsets.UTF_8).asBytes();
    }
}
