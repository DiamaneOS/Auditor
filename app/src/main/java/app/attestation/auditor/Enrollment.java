package app.attestation.auditor;

import com.google.common.io.BaseEncoding;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

// Any site can open an enrollment link naming an account of its own. So a link counts only with a
// one-time code Auditor itself sent to the real account page, which another site cannot read.
final class Enrollment {
    private static final int CODE_BYTES = 16;
    static final long CODE_LIFETIME_MS = 10 * 60 * 1000;
    private static final int SUBSCRIBE_KEY_BYTES = 32;

    record Account(long userId, String subscribeKey, int interval) {}

    private Enrollment() {}

    // The account data of a QR code or link: domain, user id, subscribe key, interval.
    static Account parseAccount(final String contents) {
        final String[] values = contents.split(" ");
        if (values.length < 4 || !RemoteVerifyJob.DOMAIN.equals(values[0])) {
            return null;
        }
        try {
            final long userId = Long.parseLong(values[1]);
            final int interval = Integer.parseInt(values[3]);
            if (userId <= 0 || Base64.getDecoder().decode(values[2]).length != SUBSCRIBE_KEY_BYTES) {
                return null;
            }
            return new Account(userId, values[2], interval);
        } catch (final IllegalArgumentException e) {
            return null;
        }
    }

    static String newCode() {
        final byte[] code = new byte[CODE_BYTES];
        new SecureRandom().nextBytes(code);
        return BaseEncoding.base16().lowerCase().encode(code);
    }

    static boolean codeAccepted(final String issued, final long issuedAt, final String presented, final long now) {
        return issued != null && presented != null
                && now >= issuedAt && now - issuedAt < CODE_LIFETIME_MS
                && MessageDigest.isEqual(issued.getBytes(StandardCharsets.UTF_8),
                        presented.getBytes(StandardCharsets.UTF_8));
    }
}
