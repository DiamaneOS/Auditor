DiamaneOS fork of [GrapheneOS Auditor](https://github.com/GrapheneOS/Auditor). Release builds use the
package ID `de.diamaneos.auditor`. The Java packages are unchanged.

Differences from upstream:

- Fairphone 6 support. It has no StrongBox, so its pairings use the TEE with a pairing-specific
  attest key.
- Release Auditees signed with the DiamaneOS Auditor key or GrapheneOS's are trusted. A pairing
  keeps the signer it started with.
- Remote verification uses attestation.diamaneos.de. No sample submission.

Upstream overview: https://attestation.app/about.
