package app.attestation.auditor;

import static android.graphics.Color.BLACK;
import static android.graphics.Color.WHITE;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.SystemClock;
import android.text.Html;
import android.text.Spanned;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.widget.LinearLayout;

import androidx.activity.EdgeToEdge;
import androidx.activity.OnBackPressedCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.preference.PreferenceManager;

import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.snackbar.Snackbar;
import com.google.common.collect.ImmutableSet;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.zip.DataFormatException;

import app.attestation.auditor.databinding.ActivityAttestationBinding;

public class AttestationActivity extends AppCompatActivity {
    private static final String TAG = "AttestationActivity";

    private static final String TUTORIAL_URL = "https://" + RemoteVerifyJob.DOMAIN + "/tutorial";

    private static final String STATE_AUDITEE_PAIRING = "auditee_pairing";
    private static final String STATE_AUDITEE_SERIALIZED_ATTESTATION = "auditee_serialized_attestation";
    private static final String STATE_AUDITOR_CHALLENGE = "auditor_challenge";
    private static final String STATE_AUDITOR_CHALLENGE_TIME = "auditor_challenge_time";
    private static final String STATE_STAGE = "stage";
    private static final String STATE_OUTPUT = "output";
    private static final String STATE_BACKGROUND_RESOURCE = "background_resource";

    private static final int PERMISSIONS_REQUEST_CAMERA = 0;
    private static final int PERMISSIONS_REQUEST_POST_NOTIFICATIONS_REMOTE_VERIFY = 1;
    private static final int PERMISSIONS_REQUEST_POST_NOTIFICATIONS_LINK = 2;

    // DiamaneOS: remote enrollment from the account page and from the Setup Wizard
    static final String ACTION_ADD_THIS_PHONE = "de.diamaneos.auditor.action.ADD_THIS_PHONE";
    private static final String ENROLL_SCHEME = "diamaneos-auditor";
    private static final String ENROLL_HOST = "enroll";
    private static final String ADD_THIS_PHONE_URL = "https://" + RemoteVerifyJob.DOMAIN + "/#add-this-phone";

    private static final ExecutorService executor = Executors.newSingleThreadExecutor();

    private ActivityAttestationBinding binding;
    private Snackbar snackbar;

    private enum Stage {
        None,
        Auditee,
        AuditeeGenerate,
        AuditeeResults,
        Auditor,
        Result, // Auditor success/failure and Auditee failure
        EnableRemoteVerify
    }

    private Stage stage = Stage.None;
    private boolean auditeePairing;
    private byte[] auditeeSerializedAttestation;
    private byte[] auditorChallenge;
    private long auditorChallengeTime;
    private int backgroundResource;

    final ActivityResultLauncher<Intent> QRScannerActivityLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            result -> {
                if (result.getResultCode() == Activity.RESULT_OK) {
                    Intent intent = result.getData();
                    if (intent != null) {
                        final String contents = intent.getStringExtra(QRScannerActivity.EXTRA_SCAN_RESULT);
                        if (contents == null) {
                            if (stage == Stage.Auditee) {
                                stage = Stage.None;
                            }
                            return;
                        }
                        final byte[] contentsBytes;
                        contentsBytes = contents.getBytes(StandardCharsets.ISO_8859_1);
                        if (stage == Stage.Auditee) {
                            stage = Stage.AuditeeGenerate;
                            binding.content.buttons.setVisibility(View.GONE);
                            generateAttestation(contentsBytes);
                        } else if (stage == Stage.Auditor) {
                            stage = Stage.Result;
                            binding.content.imageview.setVisibility(View.GONE);
                            handleAttestation(contentsBytes);
                        } else if (stage == Stage.EnableRemoteVerify) {
                            stage = Stage.None;
                            enableRemoteVerify(contents, false);
                        } else {
                            throw new RuntimeException("received unexpected scan result");
                        }
                    } else {
                        if (stage == Stage.Auditee) {
                            stage = Stage.None;
                        }
                    }
                }
            });

    private static final boolean isSupportedAuditee = ImmutableSet.of(
            "Pixel 6",
            "Pixel 6 Pro",
            "Pixel 6a",
            "Pixel 7",
            "Pixel 7 Pro",
            "Pixel 7a",
            "Pixel Tablet",
            "Pixel Fold",
            "Pixel 8",
            "Pixel 8 Pro",
            "Pixel 8a",
            "Pixel 9",
            "Pixel 9 Pro",
            "Pixel 9 Pro XL",
            "Pixel 9 Pro Fold",
            "Pixel 9a",
            "Pixel 10",
            "Pixel 10 Pro",
            "Pixel 10 Pro XL",
            "Pixel 10 Pro Fold",
            "Pixel 10a",
            // DiamaneOS
            "The Fairphone (Gen. 6)").contains(Build.MODEL);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        EdgeToEdge.enable(this);
        super.onCreate(savedInstanceState);

        binding = ActivityAttestationBinding.inflate(getLayoutInflater());
        View rootView = binding.getRoot();
        setContentView(rootView);
        setSupportActionBar(binding.toolbar);

        ViewCompat.setOnApplyWindowInsetsListener(binding.getRoot(), (@NonNull View v, @NonNull WindowInsetsCompat insets) -> {
            Insets barInsets = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            Insets cutoutInsets = insets.getInsets(WindowInsetsCompat.Type.displayCutout());

            int leftInsets = barInsets.left + cutoutInsets.left;
            int rightInsets = barInsets.right + cutoutInsets.right;

            binding.toolbar.setPadding(leftInsets, 0, rightInsets, 0);
            binding.content.buttons.setPadding(0, 0, 0, barInsets.bottom);

            ViewGroup.MarginLayoutParams mlpScrollView = (ViewGroup.MarginLayoutParams) binding.content.scrollview.getLayoutParams();
            mlpScrollView.leftMargin = leftInsets;
            mlpScrollView.rightMargin = rightInsets;
            binding.content.scrollview.setLayoutParams(mlpScrollView);

            return insets;
        });

        snackbar = Snackbar.make(rootView, "", Snackbar.LENGTH_LONG);

        binding.content.auditee.setOnClickListener((final View view) -> {
            if (!isSupportedAuditee) {
                snackbar.setText(R.string.unsupported_auditee).show();
                return;
            }
            stage = Stage.Auditee;
            startQrScanner();
        });

        binding.content.auditor.setOnClickListener(view -> {
            snackbar.dismiss();
            stage = Stage.Auditor;
            binding.content.buttons.setVisibility(View.GONE);
            runAuditor();
        });

        if (savedInstanceState != null) {
            auditeePairing = savedInstanceState.getBoolean(STATE_AUDITEE_PAIRING);
            auditeeSerializedAttestation = savedInstanceState.getByteArray(STATE_AUDITEE_SERIALIZED_ATTESTATION);
            auditorChallenge = savedInstanceState.getByteArray(STATE_AUDITOR_CHALLENGE);
            auditorChallengeTime = savedInstanceState.getLong(STATE_AUDITOR_CHALLENGE_TIME);
            stage = Stage.valueOf(savedInstanceState.getString(STATE_STAGE));
            binding.content.textview.setText(Html.fromHtml(savedInstanceState.getString(STATE_OUTPUT),
                    Html.FROM_HTML_MODE_LEGACY));
            backgroundResource = savedInstanceState.getInt(STATE_BACKGROUND_RESOURCE);
        }

        final ViewTreeObserver vto = binding.content.imageview.getViewTreeObserver();
        vto.addOnPreDrawListener(new ViewTreeObserver.OnPreDrawListener() {
            @Override
            public boolean onPreDraw() {
                binding.content.imageview.getViewTreeObserver().removeOnPreDrawListener(this);
                if (stage != Stage.None) {
                    binding.content.buttons.setVisibility(View.GONE);
                    if (stage == Stage.AuditeeResults) {
                        auditeeShowAttestation(auditeeSerializedAttestation);
                    } else if (stage == Stage.Auditor) {
                        runAuditor();
                    }
                }
                binding.content.getRoot().setBackgroundResource(backgroundResource);
                return true;
            }
        });

        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                if (stage == Stage.AuditeeResults || stage == Stage.Auditor ||
                        stage == Stage.Result) {
                    auditeeSerializedAttestation = null;
                    auditorChallenge = null;
                    stage = Stage.None;
                    binding.content.textview.setText("");
                    backgroundResource = 0;
                    recreate();
                } else {
                    finish();
                }
            }
        });

        RemoteVerifyJob.restore(this);

        if (savedInstanceState == null) {
            handleEnrollmentIntent(getIntent());
        }
    }

    private void handleEnrollmentIntent(final Intent intent) {
        if (ACTION_ADD_THIS_PHONE.equals(intent.getAction())) {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(ADD_THIS_PHONE_URL))
                    .addCategory(Intent.CATEGORY_BROWSABLE));
            finish();
        } else if (Intent.ACTION_VIEW.equals(intent.getAction()) && intent.getData() != null
                && ENROLL_SCHEME.equals(intent.getData().getScheme())
                && ENROLL_HOST.equals(intent.getData().getHost())) {
            final String account = intent.getData().getQueryParameter("account");
            if (account == null) {
                snackbar.setText(R.string.scanned_invalid_account_qr_code).show();
            } else {
                enableRemoteVerify(account, true);
            }
        }
    }

    // Any app can send the enrollment link, so it is confirmed first. A device without a
    // manufacturer-rooted chain also needs the user to confirm how it was set up.
    private void enableRemoteVerify(final String contents, final boolean fromLink) {
        if (!isSupportedAuditee) {
            snackbar.setText(R.string.unsupported_auditee).show();
            return;
        }
        final String[] values = contents.split(" ");
        if (values.length < 4 || !RemoteVerifyJob.DOMAIN.equals(values[0])) {
            snackbar.setText(R.string.scanned_invalid_account_qr_code).show();
            return;
        }
        final long userId;
        final int interval;
        try {
            userId = Long.parseLong(values[1]);
            interval = Integer.parseInt(values[3]);
        } catch (final NumberFormatException e) {
            snackbar.setText(R.string.scanned_invalid_account_qr_code).show();
            return;
        }
        final Runnable enable = () -> {
            PreferenceManager.getDefaultSharedPreferences(this).edit()
                    .putLong(RemoteVerifyJob.KEY_USER_ID, userId)
                    .putString(RemoteVerifyJob.KEY_SUBSCRIBE_KEY, values[2])
                    .apply();
            RemoteVerifyJob.schedule(this, interval);
            binding.content.remoteVerify.setVisibility(View.GONE);
            snackbar.setText(R.string.enable_remote_verify_success).show();
            if (fromLink && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                    != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS},
                        PERMISSIONS_REQUEST_POST_NOTIFICATIONS_LINK);
            }
        };
        final Runnable checkSetup = () -> executor.submit(() -> {
            final boolean manufacturerRooted = AttestationProtocol.hasManufacturerRootedAttestation(this);
            runOnUiThread(() -> {
                if (manufacturerRooted) {
                    enable.run();
                } else {
                    confirmSetup(enable, null);
                }
            });
        });
        if (fromLink) {
            new MaterialAlertDialogBuilder(this)
                    .setTitle(R.string.action_enable_remote_verify)
                    .setMessage(R.string.enable_remote_verify_link_confirm)
                    .setPositiveButton(android.R.string.ok, (dialog, which) -> checkSetup.run())
                    .setNegativeButton(android.R.string.cancel, null)
                    .show();
        } else {
            checkSetup.run();
        }
    }

    private void confirmSetup(final Runnable pair, final Runnable cancel) {
        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.profile2_confirm_title)
                .setMessage(R.string.profile2_confirm_text)
                .setPositiveButton(R.string.pair, (dialog, which) -> pair.run())
                .setNegativeButton(android.R.string.cancel, (dialog, which) -> {
                    if (cancel != null) {
                        cancel.run();
                    }
                })
                .setCancelable(false)
                .show();
    }

    @Override
    protected void onResume() {
        super.onResume();
        final boolean isRemoteVerifyEnabled = RemoteVerifyJob.isEnabled(this);
        int visibility = View.VISIBLE;
        if (isRemoteVerifyEnabled) {
            visibility = View.GONE;
        }
        binding.content.remoteVerify.setVisibility(visibility);
        binding.content.remoteVerify.setOnClickListener(view -> {
            if (!isSupportedAuditee) {
                snackbar.setText(R.string.unsupported_auditee).show();
                return;
            }
            stage = Stage.EnableRemoteVerify;
            startQrScanner();
        });
    }

    @Override
    public void onSaveInstanceState(@NonNull final Bundle savedInstanceState) {
        super.onSaveInstanceState(savedInstanceState);
        savedInstanceState.putBoolean(STATE_AUDITEE_PAIRING, auditeePairing);
        savedInstanceState.putByteArray(STATE_AUDITEE_SERIALIZED_ATTESTATION, auditeeSerializedAttestation);
        savedInstanceState.putByteArray(STATE_AUDITOR_CHALLENGE, auditorChallenge);
        savedInstanceState.putLong(STATE_AUDITOR_CHALLENGE_TIME, auditorChallengeTime);
        savedInstanceState.putString(STATE_STAGE, stage.name());
        savedInstanceState.putString(STATE_OUTPUT, Html.toHtml((Spanned) binding.content.textview.getText(),
                Html.TO_HTML_PARAGRAPH_LINES_CONSECUTIVE));
        savedInstanceState.putInt(STATE_BACKGROUND_RESOURCE, backgroundResource);
    }

    private void chooseBestLayout(final byte[] data) {
        final ViewTreeObserver vto = binding.content.getRoot().getViewTreeObserver();
        vto.addOnPreDrawListener(new ViewTreeObserver.OnPreDrawListener() {
            @Override
            public boolean onPreDraw() {
                binding.content.getRoot().getViewTreeObserver().removeOnPreDrawListener(this);
                if (binding.content.getRoot().getHeight() - binding.content.textview.getHeight() >
                        binding.content.getRoot().getWidth() - binding.content.textview.getWidth()) {
                    binding.content.result.setOrientation(LinearLayout.VERTICAL);

                    final ViewTreeObserver vto = binding.content.imageview.getViewTreeObserver();
                    vto.addOnPreDrawListener(new ViewTreeObserver.OnPreDrawListener() {
                        @Override
                        public boolean onPreDraw() {
                            binding.content.imageview.getViewTreeObserver().removeOnPreDrawListener(this);
                            binding.content.imageview.setImageBitmap(createQrCode(data));
                            return true;
                        }
                    });
                } else {
                    binding.content.imageview.setImageBitmap(createQrCode(data));
                }
                return true;
            }
        });
    }

    private void runAuditor() {
        if (auditorChallenge == null) {
            auditorChallenge = AttestationProtocol.getChallengeMessage(this);
            auditorChallengeTime = SystemClock.elapsedRealtime();
        }
        binding.content.textview.setText(R.string.qr_code_scan_hint_auditor);
        chooseBestLayout(auditorChallenge);
        binding.content.imageview.setOnClickListener(view -> startQrScanner());
    }

    private void handleAttestation(final byte[] serialized) {
        handleAttestation(serialized, SystemClock.elapsedRealtime() - auditorChallengeTime, false);
    }

    private void handleAttestation(final byte[] serialized, final long challengeAgeMs,
            final boolean profile2Confirmed) {
        binding.content.textview.setText(R.string.verifying_attestation);
        executor.submit(() -> {
            try {
                final AttestationProtocol.VerificationResult result = AttestationProtocol.verifySerialized(
                        this, serialized, auditorChallenge, challengeAgeMs, profile2Confirmed);
                if (result.needsConfirmation()) {
                    runOnUiThread(() -> confirmSetup(
                            () -> handleAttestation(serialized, challengeAgeMs, true),
                            () -> getOnBackPressedDispatcher().onBackPressed()));
                    return;
                }
                runOnUiThread(() -> {
                    setBackgroundResource(result.strong() ? R.color.green : R.color.orange);
                    binding.content.textview.setText(result.strong() ? R.string.verify_strong : R.string.verify_basic);
                    binding.content.textview.append(getText(R.string.hardware_enforced));
                    binding.content.textview.append(result.teeEnforced());
                    binding.content.textview.append(getText(R.string.os_enforced));
                    binding.content.textview.append(result.osEnforced());
                    if (!result.history().isEmpty()) {
                        binding.content.textview.append(getText(R.string.history));
                        binding.content.textview.append(result.history());
                    }
                });
            } catch (final BufferUnderflowException | DataFormatException |
                    GeneralSecurityException | NegativeArraySizeException e) {
                Log.e(TAG, "attestation verification error", e);
                runOnUiThread(() -> {
                    setBackgroundResource(R.color.red);
                    binding.content.textview.setText(R.string.verify_error);
                    binding.content.textview.append(e.getMessage());
                });
            }
        });
    }

    private void generateAttestation(final byte[] challenge) {
        binding.content.textview.setText(R.string.generating_attestation);
        executor.submit(() -> {
            try {
                final AttestationProtocol.AttestationResult result =
                        AttestationProtocol.generateSerialized(this, challenge, null, "");
                runOnUiThread(() -> {
                    auditeePairing = result.pairing();
                    auditeeShowAttestation(result.serialized());
                });
            } catch (final GeneralSecurityException | IOException e) {
                Log.e(TAG, "attestation generation error", e);
                runOnUiThread(() -> {
                    stage = Stage.Result;
                    setBackgroundResource(R.color.red);
                    binding.content.textview.setText(R.string.generate_error);
                    binding.content.textview.append(e.getMessage());
                });
            }
        });
    }

    private void auditeeShowAttestation(final byte[] serialized) {
        auditeeSerializedAttestation = serialized;
        stage = Stage.AuditeeResults;
        if (auditeePairing) {
            binding.content.textview.setText(R.string.qr_code_scan_hint_auditee_pairing);
        } else {
            binding.content.textview.setText(R.string.qr_code_scan_hint_auditee);
        }
        chooseBestLayout(serialized);
    }

    private Bitmap createQrCode(final byte[] contents) {
        final BitMatrix result;
        try {
            final QRCodeWriter writer = new QRCodeWriter();
            final Map<EncodeHintType,Object> hints = new EnumMap<>(EncodeHintType.class);
            hints.put(EncodeHintType.CHARACTER_SET, StandardCharsets.ISO_8859_1);
            final int size = Math.min(binding.content.imageview.getWidth(), binding.content.imageview.getHeight());
            result = writer.encode(new String(contents, StandardCharsets.ISO_8859_1), BarcodeFormat.QR_CODE,
                    size, size, hints);
        } catch (WriterException e) {
            throw new RuntimeException(e);
        }

        final int width = result.getWidth();
        final int height = result.getHeight();
        final int[] pixels = new int[width * height];
        for (int y = 0; y < height; y++) {
            final int offset = y * width;
            for (int x = 0; x < width; x++) {
                pixels[offset + x] = result.get(x, y) ? BLACK : WHITE;
            }
        }

        return Bitmap.createBitmap(pixels, width, height, Bitmap.Config.RGB_565);
    }

    @SuppressLint("InlinedApi")
    private void startQrScanner() {
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.CAMERA},
                    PERMISSIONS_REQUEST_CAMERA);
        } else {
            if (stage == Stage.EnableRemoteVerify &&
                    checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS},
                        PERMISSIONS_REQUEST_POST_NOTIFICATIONS_REMOTE_VERIFY);
            } else {
                launchQrScannerActivity();
            }
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode,
                                           @NonNull String[] permissions,
                                           @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == PERMISSIONS_REQUEST_CAMERA) {
            if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                startQrScanner();
            } else {
                snackbar.setText(R.string.camera_permission_denied).show();
            }
        } else if (requestCode == PERMISSIONS_REQUEST_POST_NOTIFICATIONS_REMOTE_VERIFY) {
            launchQrScannerActivity();
        }
    }

    private void setBackgroundResource(final int resid) {
        backgroundResource = resid;
        binding.content.getRoot().setBackgroundResource(resid);
    }

    @Override
    public void onActivityResult(final int requestCode, final int resultCode, final Intent intent) {
        super.onActivityResult(requestCode, resultCode, intent);

        Log.d(TAG, "onActivityResult " + requestCode + " " + resultCode);

    }

    @Override
    public boolean onCreateOptionsMenu(final Menu menu) {
        getMenuInflater().inflate(R.menu.menu_attestation, menu);
        menu.findItem(R.id.action_clear_auditee).setEnabled(isSupportedAuditee);
        return true;
    }

    @Override
    public boolean onPrepareOptionsMenu(final Menu menu) {
        final boolean isRemoteVerifyEnabled = RemoteVerifyJob.isEnabled(this);
        menu.findItem(R.id.action_disable_remote_verify).setEnabled(isRemoteVerifyEnabled);
        return true;
    }

    @Override
    @SuppressLint("InlinedApi")
    public boolean onOptionsItemSelected(final MenuItem item) {
        final int itemId = item.getItemId();
        if (itemId == R.id.action_clear_auditee) {
            new MaterialAlertDialogBuilder(this)
                    .setMessage(getString(R.string.action_clear_auditee) + "?")
                    .setPositiveButton(R.string.clear, (dialogInterface, i) -> {
                        executor.submit(() -> {
                            try {
                                AttestationProtocol.clearAuditee();
                                runOnUiThread(() -> snackbar.setText(R.string.clear_auditee_pairings_success).show());
                            } catch (final GeneralSecurityException | IOException e) {
                                Log.e(TAG, "clearAuditee", e);
                                runOnUiThread(() -> snackbar.setText(R.string.clear_auditee_pairings_failure).show());
                            }
                        });
                    })
                    .setNegativeButton(R.string.cancel, null)
                    .show();
            return true;
        } else if (itemId == R.id.action_clear_auditor) {
            new MaterialAlertDialogBuilder(this)
                    .setMessage(getString(R.string.action_clear_auditor) + "?")
                    .setPositiveButton(R.string.clear, (dialogInterface, i) -> {
                        executor.submit(() -> {
                            AttestationProtocol.clearAuditor(this);
                            runOnUiThread(() -> snackbar.setText(R.string.clear_auditor_pairings_success).show());
                        });
                    })
                    .setNegativeButton(R.string.cancel, null)
                    .show();
            return true;
        } else if (itemId == R.id.action_disable_remote_verify) {
            new MaterialAlertDialogBuilder(this)
                    .setMessage(getString(R.string.action_disable_remote_verify) + "?")
                    .setPositiveButton(R.string.disable, (dialogInterface, i) -> {
                        RemoteVerifyJob.executor.submit(() -> {
                            final SharedPreferences preferences =
                                    PreferenceManager.getDefaultSharedPreferences(this);
                            RemoteVerifyJob.cancel(this);

                            final long userId = preferences.getLong(RemoteVerifyJob.KEY_USER_ID, -1);

                            if (userId != -1) {
                                try {
                                    AttestationProtocol.clearAuditee(RemoteVerifyJob.STATE_PREFIX, Long.toString(userId));
                                } catch (final GeneralSecurityException | IOException e) {
                                    Log.e(TAG, "clearAuditee", e);
                                }
                            }

                            preferences.edit()
                                    .remove(RemoteVerifyJob.KEY_USER_ID)
                                    .remove(RemoteVerifyJob.KEY_SUBSCRIBE_KEY)
                                    .apply();

                            runOnUiThread(() -> snackbar.setText(R.string.disable_remote_verify_success).show());
                        });
                        binding.content.remoteVerify.setVisibility(View.VISIBLE);
                    })
                    .setNegativeButton(R.string.cancel, null)
                    .show();
            return true;
        } else if (itemId == R.id.action_help) {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(TUTORIAL_URL)));
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void launchQrScannerActivity() {
        QRScannerActivityLauncher.launch(new Intent(this, QRScannerActivity.class));
        overridePendingTransition(android.R.anim.fade_in, android.R.anim.fade_out);
    }
}
