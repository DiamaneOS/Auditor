package app.attestation.auditor;

import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.security.GeneralSecurityException;

// Input a fuzzer found. Each must be refused with an exception the Auditor shows as a failed
// verification, never one that leaves the screen on "Verifying".
public class MalformedInputTest {
    private static GeneralSecurityException verify(final AttestationFixture fixture) throws Exception {
        final ReleaseList releases = ReleaseList.parse(AttestationFixture.releaseList(AttestationFixture.LIST_SIGNER, 1,
                AttestationFixture.release(fixture.bootHash, 202610)), AttestationFixture.trust().releaseListSigners);
        return assertThrows(GeneralSecurityException.class, () -> AttestationProtocol.verifyStateless(
                fixture.chain(), fixture.challenge, false, new byte[0][], AttestationFixture.trust(),
                (device, evidence) -> Profile2.match(releases, device, evidence), 1000, ""));
    }

    @Test
    public void malformedAttestationExtension() throws Exception {
        final AttestationFixture fixture = new AttestationFixture();
        // SEQUENCE { INTEGER 3 }: a key description cut short
        fixture.leafKeyDescription = new byte[]{0x30, 0x03, 0x02, 0x01, 0x03};
        final GeneralSecurityException e = verify(fixture);
        assertTrue(e.getMessage(), e.getMessage().contains("malformed key attestation extension"));
    }
}
