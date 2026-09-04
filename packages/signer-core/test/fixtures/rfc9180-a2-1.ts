/**
 * Canonical RFC 9180 Appendix A.2.1 mode_base vector (base setup, encryption sequence 0) used by
 * every signer-core test lane.
 *
 * A.2 is DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305 — the exact locked suite this
 * package implements. An earlier revision of this citation said "A.6"; A.6 is
 * DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM, which this package does not implement. The
 * bytes below never changed and were always the A.2.1 values; only the appendix number was wrong.
 */
export const RFC9180_A2_1 = Object.freeze({
  info: "4f6465206f6e2061204772656369616e2055726e",
  skEm: "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600",
  pkEm: "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
  pkRm: "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
  skRm: "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
  plaintext: "4265617574792069732074727574682c20747275746820626561757479",
  aad: "436f756e742d30",
  ciphertext: "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
});
