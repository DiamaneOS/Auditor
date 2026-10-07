DiamaneOS fork of [GrapheneOS Auditor](https://github.com/GrapheneOS/Auditor). The package ID stays
`app.attestation.auditor`.

Differences from upstream:

- Fairphone 6 support. It has no StrongBox, so its pairings use the TEE with a pairing-specific
  attest key.
- Release Auditees must be signed with the DiamaneOS Auditor key.
- Remote verification and sample submission use attestation.diamaneos.de.

Upstream overview: https://attestation.app/about.
