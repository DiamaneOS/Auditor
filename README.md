DiamaneOS fork of [GrapheneOS Auditor](https://github.com/GrapheneOS/Auditor). Release builds use the
package ID `de.diamaneos.auditor`. The Java packages are unchanged.

Differences from upstream:

- Fairphone 6 support. It has no StrongBox, so its pairings use the TEE with a pairing-specific
  attest key.
- Phones whose secure hardware gives no manufacturer-rooted chain can pair after the person pairing
  confirms how the phone was set up. The first pairing must exactly match an official release on the
  signed release list. Results say "First pairing not verified by hardware".
- Device specifics and trusted keys are in `app/src/main/res/raw/diamaneos_trust.json`.
- Release Auditees signed with the DiamaneOS Auditor key or GrapheneOS's are trusted. A pairing
  keeps the signer it started with.
- Remote verification uses attestation.diamaneos.de, whose account page can add the phone directly.
  No sample submission.

Upstream overview: https://attestation.app/about.
