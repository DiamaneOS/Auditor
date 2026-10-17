package app.attestation.auditor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.common.io.BaseEncoding;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.util.function.Consumer;

import app.attestation.auditor.attestation.RootOfTrust;

public class Profile2Test {
    private static final byte[][] NO_MANUFACTURER_ROOTS = new byte[0][];

    private static ReleaseList list(final byte[]... bootHashes) throws Exception {
        final org.json.JSONObject[] releases = new org.json.JSONObject[bootHashes.length];
        for (int i = 0; i < bootHashes.length; i++) {
            releases[i] = AttestationFixture.release(bootHashes[i], 202610);
        }
        return ReleaseList.parse(AttestationFixture.releaseList(AttestationFixture.LIST_SIGNER, 1, releases),
                AttestationFixture.trust().releaseListSigners);
    }

    private static AttestationProtocol.Verified verify(final AttestationFixture fixture,
            final boolean hasPersistentKey, final long challengeAgeMs, final ReleaseList releases)
            throws Exception {
        final Certificate[] chain = fixture.chain();
        return AttestationProtocol.verifyStateless(chain, fixture.challenge, hasPersistentKey,
                NO_MANUFACTURER_ROOTS, AttestationFixture.trust(),
                (device, evidence) -> Profile2.match(releases, device, evidence), challengeAgeMs);
    }

    private static void rejected(final String reason, final Consumer<AttestationFixture> change)
            throws Exception {
        final AttestationFixture fixture = new AttestationFixture();
        final ReleaseList releases = list(fixture.bootHash);
        change.accept(fixture);
        final GeneralSecurityException e = assertThrows(GeneralSecurityException.class,
                () -> verify(fixture, false, 1000, releases));
        assertTrue(e.getMessage(), e.getMessage().contains(reason));
    }

    @Test
    public void firstPairingMatchingOfficialRelease() throws Exception {
        final AttestationFixture fixture = new AttestationFixture();
        final AttestationProtocol.Verified verified = verify(fixture, false, 1000, list(fixture.bootHash));
        assertNotNull(verified.profile2Device());
        assertEquals("FP6", verified.profile2Device().id());
        assertTrue(verified.reviewFlags().isEmpty());
    }

    @Test
    public void firstPairingRejections() throws Exception {
        final String notOfficial = "not an official release";
        final String mismatch = "do not match official release";
        rejected(notOfficial, f -> f.bootHash = AttestationFixture.sha256("unpublished build"));
        rejected(mismatch, f -> f.osPatchLevel = 202609);
        rejected(mismatch, f -> f.vendorPatchLevel = 20260905);
        rejected(mismatch, f -> f.bootPatchLevel = 20260905);
        rejected(mismatch, f -> f.keyMintVersion = 400);
        rejected(mismatch, f -> f.attestationVersion = 400);
        rejected("not locked", f -> f.locked = false);
        rejected("not self signed", f -> f.state = RootOfTrust.VerifiedBootState.VERIFIED);
        rejected("invalid verified boot key", f -> f.bootKey = AttestationFixture.sha256("other OS key"));
        rejected("signing key", f -> f.signer = AttestationFixture.sha256("other signer"));
        rejected("requires the DiamaneOS Auditor", f -> {
            f.packageName = "app.attestation.auditor";
            f.signer = BaseEncoding.base16().decode(
                    "990E04F0864B19F14F84E0E432F7A393F297AB105A22C1E1B10B442A4A62C42C");
        });
        rejected("attest key challenge", f -> f.attestChallenge = AttestationFixture.sha256("other"));
        rejected("not a valid key attestation root", f -> f.rootExtension = true);
    }

    @Test
    public void staleOrReplayedChallengeRejected() throws Exception {
        final AttestationFixture fixture = new AttestationFixture();
        final ReleaseList releases = list(fixture.bootHash);
        assertThrows(GeneralSecurityException.class,
                () -> verify(fixture, false, Profile2.LOCAL_CHALLENGE_LIFETIME_MS + 1, releases));
        final Certificate[] chain = fixture.chain();
        assertThrows(GeneralSecurityException.class, () -> AttestationProtocol.verifyStateless(chain,
                AttestationFixture.sha256("expected challenge"), false, NO_MANUFACTURER_ROOTS,
                AttestationFixture.trust(), (device, evidence) -> Profile2.match(releases, device, evidence),
                1000));
    }

    @Test
    public void laterCheckFollowsTheReleaseList() throws Exception {
        final AttestationFixture fixture = new AttestationFixture();
        fixture.attestChallenge = fixture.challenge;
        fixture.challenge = AttestationFixture.sha256("next challenge");
        fixture.leaf = AttestationFixture.keyPair();
        final byte[] update = AttestationFixture.sha256("release 2");
        fixture.bootHash = update;
        // an approved update passes once published, without a time limit on later checks
        assertNotNull(verify(fixture, true, Long.MAX_VALUE, list(AttestationFixture.sha256("release 1"), update))
                .profile2Device());
        assertThrows(GeneralSecurityException.class, () -> verify(fixture, true, 0,
                list(AttestationFixture.sha256("release 1"))));
    }

    @Test
    public void chainShape() throws Exception {
        final Certificate[] chain = new AttestationFixture().chain();
        assertThrows(GeneralSecurityException.class,
                () -> Profile2.checkChainShape(new Certificate[]{chain[0], chain[1]}));
        assertThrows(GeneralSecurityException.class,
                () -> Profile2.checkChainShape(new Certificate[]{chain[0], chain[1], chain[2], chain[2]}));
    }

    @Test
    public void reviewFlagsNeverReject() throws Exception {
        final Certificate[] chain = new AttestationFixture().chain();
        assertTrue(Profile2.reviewFlags(chain).isEmpty());
        assertTrue(Profile2.reviewFlags(new Certificate[]{chain[1], chain[0], chain[2]}).contains("extensions"));
    }

    @Test
    public void releaseListSignature() throws Exception {
        final TrustConfig trust = AttestationFixture.trust();
        final byte[] hash = AttestationFixture.sha256("release 1");
        final byte[] signed = AttestationFixture.releaseList(AttestationFixture.LIST_SIGNER, 3,
                AttestationFixture.release(hash, 202610));
        final ReleaseList list = ReleaseList.parse(signed, trust.releaseListSigners);
        assertEquals(3, list.sequence);
        assertNotNull(list.find("FP6", BaseEncoding.base16().encode(AttestationFixture.AVB_KEY),
                BaseEncoding.base16().encode(hash)));
        assertNull(list.find("FP6", BaseEncoding.base16().encode(AttestationFixture.AVB_KEY),
                BaseEncoding.base16().encode(AttestationFixture.sha256("other"))));

        assertThrows(GeneralSecurityException.class, () -> ReleaseList.parse(
                AttestationFixture.releaseList(AttestationFixture.keyPair(), 3,
                        AttestationFixture.release(hash, 202610)), trust.releaseListSigners));
        final String tampered = new String(signed, StandardCharsets.UTF_8).replace("\"payload\":\"",
                "\"payload\":\"ey");
        assertThrows(GeneralSecurityException.class, () -> ReleaseList.parse(
                tampered.getBytes(StandardCharsets.UTF_8), trust.releaseListSigners));
    }

    @Test
    public void productionTrustConfig() throws Exception {
        final TrustConfig trust = TrustConfig.parse(new String(Files.readAllBytes(
                Path.of("src/main/res/raw/diamaneos_trust.json")), StandardCharsets.UTF_8));
        assertEquals(64, trust.auditorReleaseSigner.length());
        assertEquals(1, trust.devices.size());
        assertThrows(GeneralSecurityException.class, () -> TrustConfig.parse("{\"format\":\"other\",\"version\":1}"));
    }
}
