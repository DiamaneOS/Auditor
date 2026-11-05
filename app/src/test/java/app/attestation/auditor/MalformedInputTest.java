package app.attestation.auditor;

import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

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

    @Test
    public void appVersionOutOfRange() throws Exception {
        final AttestationFixture fixture = new AttestationFixture();
        for (final long version : new long[]{1L << 33, Long.MIN_VALUE + fixture.appVersion}) {
            fixture.appVersion = version;
            final GeneralSecurityException e = verify(fixture);
            assertTrue(e.getMessage(), e.getMessage().contains("app version out of range"));
        }
    }

    @Test
    public void emptyCertificateChain() throws Exception {
        final byte[] dictionary = Files.readAllBytes(Path.of("src/main/res/raw/deflate_dictionary_5.bin"));
        final ByteArrayOutputStream compressed = new ByteArrayOutputStream();
        final Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION, true);
        deflater.setDictionary(dictionary);
        try (DeflaterOutputStream stream = new DeflaterOutputStream(compressed, deflater)) {
            stream.finish();
        }
        deflater.end();
        final Method decodeChain = AttestationProtocol.class.getDeclaredMethod("decodeChain", byte[].class, byte[].class);
        decodeChain.setAccessible(true);
        final InvocationTargetException e = assertThrows(InvocationTargetException.class,
                () -> decodeChain.invoke(null, dictionary, compressed.toByteArray()));
        assertTrue(String.valueOf(e.getCause()), e.getCause() instanceof GeneralSecurityException);
    }
}
