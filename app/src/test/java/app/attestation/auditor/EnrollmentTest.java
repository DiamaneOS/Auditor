package app.attestation.auditor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.Base64;

public class EnrollmentTest {
    private static final String KEY = Base64.getEncoder().encodeToString(new byte[32]);

    private static Enrollment.Account parse(final String userId, final String key) {
        return Enrollment.parseAccount(RemoteVerifyJob.DOMAIN + " " + userId + " " + key + " 21600");
    }

    @Test
    public void accountAsTheServerSendsIt() {
        final Enrollment.Account account = parse("7", KEY);
        assertNotNull(account);
        assertEquals(7, account.userId());
        assertEquals(KEY, account.subscribeKey());
        assertEquals(21600, account.interval());
    }

    @Test
    public void badAccountsAreRefused() {
        assertNull(Enrollment.parseAccount("other.example 7 " + KEY + " 21600"));
        assertNull(Enrollment.parseAccount(RemoteVerifyJob.DOMAIN + " 7 " + KEY));
        assertNull(parse("0", KEY));
        assertNull(parse("-1", KEY));
        assertNull(parse("x", KEY));
        assertNull(parse("7", "a\nb"));
        assertNull(parse("7", Base64.getEncoder().encodeToString(new byte[31])));
        assertNull(Enrollment.parseAccount(RemoteVerifyJob.DOMAIN + " 7 " + KEY + " x"));
    }

    @Test
    public void onlyTheIssuedFreshCodeIsAccepted() {
        final String code = Enrollment.newCode();
        assertEquals(32, code.length());
        assertNotEquals(code, Enrollment.newCode());
        final long issued = 1000;
        assertTrue(Enrollment.codeAccepted(code, issued, code, issued + 1));
        assertFalse(Enrollment.codeAccepted(code, issued, code, issued + Enrollment.CODE_LIFETIME_MS));
        assertFalse(Enrollment.codeAccepted(code, issued, code, issued - 1));
        assertFalse(Enrollment.codeAccepted(code, issued, null, issued + 1));
        assertFalse(Enrollment.codeAccepted(code, issued, "0".repeat(32), issued + 1));
        assertFalse(Enrollment.codeAccepted(null, issued, code, issued + 1));
    }
}
