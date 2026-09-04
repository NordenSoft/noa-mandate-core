/**
 * #77-C — WHAT THE HUMAN SEES MUST BE WHAT WAS SEALED.
 *
 * This is the product's core failure mode reached without touching a key, forging a signature, or
 * holding a network position. Every cryptographic check passes and the human approves the wrong
 * thing.
 *
 * ─── C/1: THE DISPLAY IS INTERPRETED THROUGH WRITABLE GLOBALS *AFTER* THE AEAD VERIFIES ─────────
 *
 *     const parsed = JSON.parse(new TextDecoder().decode(plaintext)) as unknown;
 *
 * By this line the ciphertext has already been authenticated. Both `TextDecoder.prototype.decode`
 * and the global `JSON.parse` are writable slots, so what the approver is SHOWN is decided after
 * authentication by something an attacker can replace. MEASURED, real seal→open with a real x25519
 * device key, live control and clean restoration:
 *
 *     CONTROL  human is shown -> "Wire EUR 2,400,000 to NEW payee GmbH"
 *     ATTACK   human is shown -> "Refund EUR 1.00 to Alice"      (via TextDecoder.decode)
 *     ATTACK   human is shown -> "Refund EUR 1.00 to Alice"      (via JSON.parse)
 *     POST     human is shown -> "Wire EUR 2,400,000 to NEW payee GmbH"
 *
 * ─── C/2: THE RECIPIENT SET IS BUILT THROUGH `Array.prototype.map` AT SEAL TIME ─────────────────
 *
 * MEASURED — this was a reviewer CLAIM until it was run:
 *     sealed recipients -> attacker-device
 *     attacker opens    -> "Wire EUR 2,400,000 to NEW payee GmbH"
 *     real approver     -> LOCKED OUT ("no recipient entry")
 * At seal time the CEK is in hand, so substituting the list genuinely hands the display to the
 * attacker AND denies it to the intended approver.
 *
 * ─── ATTACKER · VICTIM · CAPABILITY · OUTCOME ───────────────────────────────────────────────────
 *
 *   attacker    same-realm code loaded before the approval is rendered
 *   victim      the human approver, and the tenant they approve for
 *   capability  prototype pollution ONLY — no key, no signature forgery, no network position
 *   outcome     a genuine, correctly-signed approval attributed to a real human for an action they
 *               were never shown
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { runInNewContext } from "node:vm";
import { decodeX25519PublicKey, sealEncryptedDisplay, openEncryptedDisplay } from "../src/encrypted-display.js";
import { base64ToBytes, bytesToBase64, bytesToHex } from "../src/bytes.js";
import { canonicalize } from "../src/jcs.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";

const DANGEROUS = { title: "Wire EUR 2,400,000 to NEW payee GmbH", risk: "CRITICAL", summary: ["payee: unrecognised"] };
const BENIGN_TITLE = "Refund EUR 1.00 to Alice";

/** Install a poisoned member, run `body`, restore the EXACT prior descriptor. */
function withPoison<T>(target: object, key: string, value: unknown, body: () => T): T {
  const prior = Object.getOwnPropertyDescriptor(target, key);
  Object.defineProperty(target, key, { value, writable: true, configurable: true });
  try {
    return body();
  } finally {
    if (prior === undefined) delete (target as Record<string, unknown>)[key];
    else Object.defineProperty(target, key, prior);
  }
}

function fixture() {
  const device = x25519.keygen();
  const kid = "approver-1-device-1";
  const ed = sealEncryptedDisplay({
    tenant: "acme-tenant",
    holdId: "hold-abc",
    deferredReceiptHash: "sha256:" + "a".repeat(64),
    expiresAt: "2026-07-15T12:05:00.000Z",
    display: DANGEROUS,
    recipients: [{ kid, hpkePublicKey: bytesToHex(device.publicKey) }],
  });
  return { device, kid, ed, open: () => openEncryptedDisplay(ed, { kid, secretKey: device.secretKey }) };
}

function x25519SpkiBase64(publicKey: Uint8Array): string {
  const prefix = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00];
  const spki = new Uint8Array(44);
  for (let i = 0; i < prefix.length; i++) spki[i] = prefix[i] as number;
  for (let i = 0; i < 32; i++) spki[12 + i] = publicKey[i] as number;
  return bytesToBase64(spki);
}

// ────────────────────────────────────────────────────────────────────────────────────────────────
// C/1 — the rendered display must come from the authenticated plaintext, not from a live global.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("#77-C/1: a poisoned `TextDecoder.prototype.decode` cannot substitute what the human sees", () => {
  const f = fixture();
  assert.equal(f.open()["title"], DANGEROUS.title, "the control is broken before the attack even starts");

  // PROOF THE VEHICLE IS LIVE: the poison must actually be reachable in this runtime.
  let fired = 0;
  withPoison(TextDecoder.prototype, "decode", function () { fired++; return "{}"; }, () => {
    new TextDecoder().decode(new Uint8Array([1]));
  });
  assert.ok(fired > 0, "`TextDecoder.prototype.decode` was not consulted — the fixture is not hostile");

  const shown = withPoison(TextDecoder.prototype, "decode",
    function () { return JSON.stringify({ title: BENIGN_TITLE, risk: "LOW" }); },
    () => {
      try { return { ok: true as const, title: f.open()["title"] }; }
      catch (e) { return { ok: false as const, err: e as Error }; }
    });

  if (shown.ok) {
    assert.equal(shown.title, DANGEROUS.title,
      "THE AEAD VERIFIED AND THE HUMAN WAS SHOWN A DIFFERENT ACTION THAN THE ONE SEALED. The " +
      "approval this produces is genuine, correctly signed, and attributed to a human who never " +
      "saw the action they authorised");
  }
  assert.equal(f.open()["title"], DANGEROUS.title, "the guarantee did not return after the poison was removed");
});

test("#77-C/1: a poisoned global `JSON.parse` cannot substitute what the human sees", () => {
  const f = fixture();
  const shown = withPoison(JSON, "parse", function () { return { title: BENIGN_TITLE, risk: "LOW" }; },
    () => {
      try { return { ok: true as const, title: f.open()["title"] }; }
      catch (e) { return { ok: false as const, err: e as Error }; }
    });
  if (shown.ok) {
    assert.equal(shown.title, DANGEROUS.title,
      "the display was replaced through the global `JSON.parse` after the AEAD had verified");
  }
  assert.equal(f.open()["title"], DANGEROUS.title, "the guarantee did not return after the poison was removed");
});

test("#77-C/1: a post-load `TextEncoder.encode` poison cannot replace the display before AEAD", () => {
  const device = x25519.keygen();
  const kid = "approver-1-device-1";
  const realEncode = TextEncoder.prototype.encode;
  const dangerousCanonical = canonicalize(DANGEROUS);
  const benignCanonical = canonicalize({ title: BENIGN_TITLE, risk: "LOW" });
  let fired = 0;

  const sealed = withPoison(TextEncoder.prototype, "encode",
    function (this: object, value = "") {
      fired++;
      return Reflect.apply(realEncode, this, [value === dangerousCanonical ? benignCanonical : value]) as Uint8Array;
    },
    () => {
      new TextEncoder().encode(dangerousCanonical);
      assert.equal(fired, 1, "the TextEncoder poison did not bite on its direct witness");
      const result = sealEncryptedDisplay({
        tenant: "acme-tenant", holdId: "hold-abc",
        deferredReceiptHash: "sha256:" + "a".repeat(64), expiresAt: "2026-07-15T12:05:00.000Z",
        display: DANGEROUS, recipients: [{ kid, hpkePublicKey: bytesToHex(device.publicKey) }],
      });
      assert.equal(fired, 1, "the sealer consulted the post-load TextEncoder poison");
      return result;
    });

  assert.deepEqual(
    openEncryptedDisplay(sealed, { kid, secretKey: device.secretKey }),
    DANGEROUS,
    "the authenticated plaintext was replaced before AEAD by a post-load TextEncoder poison",
  );
});

test("#77-C/1: a post-load `TextEncoder.encode` poison cannot rewrite HPKE schedule labels", () => {
  const realEncode = TextEncoder.prototype.encode;
  let fired = 0;
  const sealed = withPoison(TextEncoder.prototype, "encode",
    function (this: object, value = "") {
      fired++;
      const replacement = value === "HPKE-v1" || value === "eae_prk" || value === "shared_secret"
        ? "attacker-controlled-hpke-label"
        : value;
      return Reflect.apply(realEncode, this, [replacement]) as Uint8Array;
    },
    () => {
      new TextEncoder().encode("HPKE-v1");
      assert.equal(fired, 1, "the HPKE-label poison did not bite on its direct witness");
      const result = fixture();
      assert.equal(fired, 1, "HPKE consulted the post-load TextEncoder poison");
      return result;
    });

  assert.equal(
    sealed.open()["title"],
    DANGEROUS.title,
    "the HPKE schedule depended on a writable post-load TextEncoder slot",
  );
});

test("#77-C/1: inherited deterministic material cannot disclose a production display", () => {
  const device = x25519.keygen();
  const kid = "approver-1-device-1";
  const attackerKnown = {
    cek: new Uint8Array(32).fill(0x41),
    payloadNonce: new Uint8Array(12).fill(0x42),
    ephemeralSecretKey: new Uint8Array(32).fill(0x43),
  };

  const caught = withPoison(Object.prototype, "deterministic", attackerKnown, () => {
    assert.equal(({} as { deterministic?: unknown }).deterministic, attackerKnown,
      "the inherited deterministic poison did not bite on its direct witness");
    try {
      sealEncryptedDisplay({
        tenant: "acme-tenant", holdId: "hold-abc",
        deferredReceiptHash: "sha256:" + "a".repeat(64), expiresAt: "2026-07-15T12:05:00.000Z",
        display: DANGEROUS, recipients: [{ kid, hpkePublicKey: bytesToHex(device.publicKey) }],
      });
    } catch (error) {
      return error;
    }
    return undefined;
  });
  assert.match(String(caught), /runtime intrinsic integrity check failed: Object\.prototype/,
    "the sealer continued after inherited deterministic material changed Object.prototype");

  const sealed = sealEncryptedDisplay({
    tenant: "acme-tenant", holdId: "hold-abc",
    deferredReceiptHash: "sha256:" + "a".repeat(64), expiresAt: "2026-07-15T12:05:00.000Z",
    display: DANGEROUS, recipients: [{ kid, hpkePublicKey: bytesToHex(device.publicKey) }],
  });

  const aad = new TextEncoder().encode(canonicalize({
    tenant: sealed.tenant,
    holdId: sealed.holdId,
    deferredReceiptHash: sealed.deferredReceiptHash,
    expiresAt: sealed.expiresAt,
  }));
  assert.throws(
    () => chacha20poly1305(attackerKnown.cek, attackerKnown.payloadNonce, aad)
      .decrypt(base64ToBytes(sealed.payload.ciphertext)),
    /invalid tag|decrypt/i,
    "an inherited Object.prototype test hook made the CEK and nonce attacker-known",
  );
  assert.deepEqual(
    openEncryptedDisplay(sealed, { kid, secretKey: device.secretKey }),
    DANGEROUS,
    "rejecting ambient deterministic material broke the honest recipient path",
  );
});

test("#77-C/1: a post-load getRandomValues poison cannot choose CEK, nonce, or HPKE scalar", () => {
  const device = x25519.keygen();
  const kid = "approver-1-device-1";
  const cryptoPrototype = Object.getPrototypeOf(globalThis.crypto) as object;
  const prior = Object.getOwnPropertyDescriptor(cryptoPrototype, "getRandomValues");
  assert.ok(prior && typeof prior.value === "function", "Crypto.getRandomValues descriptor is unavailable");
  let poisonCalls = 0;

  const caught = withPoison(cryptoPrototype, "getRandomValues",
    function <T extends ArrayBufferView | null>(array: T): T {
      poisonCalls++;
      if (array instanceof Uint8Array) {
        const value = array.length === 12 ? 0x42 : 0x41;
        for (let i = 0; i < array.length; i++) array[i] = value;
      }
      return array;
    },
    () => {
      const witness = globalThis.crypto.getRandomValues(new Uint8Array(1));
      assert.equal(witness[0], 0x41, "the CSPRNG poison did not bite on its direct witness");
      try {
        sealEncryptedDisplay({
          tenant: "acme-tenant", holdId: "hold-abc",
          deferredReceiptHash: "sha256:" + "a".repeat(64), expiresAt: "2026-07-15T12:05:00.000Z",
          display: DANGEROUS, recipients: [{ kid, hpkePublicKey: bytesToHex(device.publicKey) }],
        });
      } catch (error) {
        return error;
      }
      return undefined;
    });

  assert.equal(poisonCalls, 1, "production sealing consulted the post-load getRandomValues poison");
  assert.match(String(caught), /runtime intrinsic integrity check failed/,
    "production sealing continued after its effective CSPRNG lookup changed");
  const sealed = sealEncryptedDisplay({
    tenant: "acme-tenant", holdId: "hold-abc",
    deferredReceiptHash: "sha256:" + "a".repeat(64), expiresAt: "2026-07-15T12:05:00.000Z",
    display: DANGEROUS, recipients: [{ kid, hpkePublicKey: bytesToHex(device.publicKey) }],
  });
  assert.deepEqual(openEncryptedDisplay(sealed, { kid, secretKey: device.secretKey }), DANGEROUS);
});

// ────────────────────────────────────────────────────────────────────────────────────────────────
// C/2 — the sealed recipient set must be the caller's, not a poisoned iterator's.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("#77-C/2: a poisoned `Array.prototype.map` cannot substitute the trusted device list", () => {
  const device = x25519.keygen();
  const attacker = x25519.keygen();
  const kid = "approver-1-device-1";
  const intended = [{ kid, hpkePublicKey: bytesToHex(device.publicKey) }];
  const realMap = Array.prototype.map;
  let fired = 0;

  const caught = withPoison(Array.prototype, "map",
    function (this: unknown[], cb: (v: unknown, i: number, a: unknown[]) => unknown, thisArg?: unknown) {
      fired++;
      if (this === intended) {
        return [cb.call(thisArg, { kid: "attacker-device", hpkePublicKey: bytesToHex(attacker.publicKey) }, 0, this)];
      }
      return (realMap as (c: unknown, t?: unknown) => unknown[]).call(this, cb, thisArg);
    },
    () => {
      assert.deepEqual(intended.map((recipient) => recipient.kid), ["attacker-device"],
        "the Array.map poison did not bite on its direct witness");
      try {
        sealEncryptedDisplay({
          tenant: "acme-tenant", holdId: "hold-abc",
          deferredReceiptHash: "sha256:" + "a".repeat(64), expiresAt: "2026-07-15T12:05:00.000Z",
          display: DANGEROUS, recipients: intended,
        });
      } catch (error) {
        return error;
      }
      return undefined;
    });

  assert.ok(fired > 0, "the Array.map poison was not exercised");
  assert.match(String(caught), /runtime intrinsic integrity check failed/,
    "the sealer continued in a realm with a post-load Array prototype mutation");

  const sealed = sealEncryptedDisplay({
    tenant: "acme-tenant", holdId: "hold-abc",
    deferredReceiptHash: "sha256:" + "a".repeat(64), expiresAt: "2026-07-15T12:05:00.000Z",
    display: DANGEROUS, recipients: intended,
  });
  assert.deepEqual(sealed.recipients.map((r) => r.kid), [kid],
    "the SEALED recipient list is not the caller's — a poisoned iterator chose who may read this " +
    "approval, handing it to an attacker and locking out the intended approver");

  // and the intended approver must still be able to open it
  const opened = openEncryptedDisplay(sealed, { kid, secretKey: device.secretKey });
  assert.equal(opened["title"], DANGEROUS.title, "the intended approver cannot open a display sealed for them");
});

test("#77-C/2: a post-entry self-restoring Array.map cannot substitute the trusted device list", () => {
  const intended = x25519.keygen();
  const attacker = x25519.keygen();
  const intendedKid = "intended-device";
  const source = [{ kid: intendedKid, hpkePublicKey: bytesToHex(intended.publicKey) }];
  let recipients: typeof source;

  const mapDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, "map");
  assert.ok(mapDescriptor && typeof mapDescriptor.value === "function" && mapDescriptor.configurable,
    "Array.prototype.map descriptor is unavailable for the attack witness");
  const realMap = mapDescriptor.value as (callback: (value: unknown, index: number, array: unknown[]) => unknown,
    thisArg?: unknown) => unknown[];
  let mapCalls = 0;
  const installRedirect = () => {
    Object.defineProperty(Array.prototype, "map", {
      ...mapDescriptor,
      value: function poisonedMap(
        this: unknown[],
        callback: (value: unknown, index: number, array: unknown[]) => unknown,
        thisArg?: unknown,
      ) {
        mapCalls++;
        Object.defineProperty(Array.prototype, "map", mapDescriptor);
        if (this === recipients) {
          return [callback.call(thisArg, {
            kid: "attacker-device",
            hpkePublicKey: bytesToHex(attacker.publicKey),
          }, 0, this)];
        }
        return Reflect.apply(realMap, this, [callback, thisArg]);
      },
    });
  };

  let proxyCalls = 0;
  let redirectInstalled = false;
  recipients = new Proxy(source, {
    getOwnPropertyDescriptor(target, key) {
      proxyCalls++;
      if (key === "length" && !redirectInstalled) {
        redirectInstalled = true;
        installRedirect();
      }
      return Reflect.getOwnPropertyDescriptor(target, key);
    },
  });

  installRedirect();
  assert.deepEqual([1].map((value) => value), [1], "the self-restoring map witness changed its control array");
  assert.equal(Array.prototype.map, realMap, "the map witness did not self-restore");
  const witnessCalls = mapCalls;

  let caught: unknown;
  try {
    try {
      sealEncryptedDisplay({
        tenant: "acme-tenant",
        holdId: "hold-self-restoring-map",
        deferredReceiptHash: "sha256:" + "a".repeat(64),
        expiresAt: "2026-07-15T12:05:00.000Z",
        display: DANGEROUS,
        recipients,
      });
    } catch (error) {
      caught = error;
    }
  } finally {
    Object.defineProperty(Array.prototype, "map", mapDescriptor);
  }

  assert.ok(proxyCalls > 0, "the recipients Proxy did not bite on its descriptor path");
  assert.equal(redirectInstalled, true, "the post-entry map redirect was never installed");
  assert.equal(mapCalls, witnessCalls,
    "recipient normalization dispatched through the attacker-selected self-restoring Array.map");
  assert.match(String(caught), /runtime intrinsic integrity check failed: Array\.prototype/,
    "the final fence accepted a post-entry Array prototype mutation");

  const honest = sealEncryptedDisplay({
    tenant: "acme-tenant",
    holdId: "hold-self-restoring-map",
    deferredReceiptHash: "sha256:" + "a".repeat(64),
    expiresAt: "2026-07-15T12:05:00.000Z",
    display: DANGEROUS,
    recipients: source,
  });
  assert.deepEqual(honest.recipients.map(({ kid }) => kid), [intendedKid]);
  assert.deepEqual(openEncryptedDisplay(honest, { kid: intendedKid, secretKey: intended.secretKey }), DANGEROUS,
    "closing the self-restoring map redirect broke the intended recipient path");
});

test("#77-C/2: a poisoned raw-key parser cannot redirect the CEK to an attacker device", () => {
  const device = x25519.keygen();
  const attacker = x25519.keygen();
  const kid = "approver-1-device-1";
  let fired = 0;

  const caught = withPoison(String.prototype, "toLowerCase",
    function () { fired++; return bytesToHex(attacker.publicKey); },
    () => {
      "witness".toLowerCase();
      assert.equal(fired, 1, "the raw-key parser poison did not bite on its direct witness");
      try {
        sealEncryptedDisplay({
          tenant: "acme-tenant", holdId: "hold-abc",
          deferredReceiptHash: "sha256:" + "a".repeat(64), expiresAt: "2026-07-15T12:05:00.000Z",
          display: DANGEROUS, recipients: [{ kid, hpkePublicKey: bytesToHex(device.publicKey) }],
        });
      } catch (error) {
        return error;
      }
      return undefined;
    });
  assert.equal(fired, 1, "the recipient-key decoder consulted String.prototype.toLowerCase");
  assert.match(String(caught), /runtime intrinsic integrity check failed: String\.prototype/,
    "the sealer continued after String.prototype changed");

  const sealed = sealEncryptedDisplay({
    tenant: "acme-tenant", holdId: "hold-abc",
    deferredReceiptHash: "sha256:" + "a".repeat(64), expiresAt: "2026-07-15T12:05:00.000Z",
    display: DANGEROUS, recipients: [{ kid, hpkePublicKey: bytesToHex(device.publicKey) }],
  });

  assert.equal(
    openEncryptedDisplay(sealed, { kid, secretKey: device.secretKey })["title"],
    DANGEROUS.title,
    "the intended device was replaced while its public key was decoded",
  );
  assert.throws(
    () => openEncryptedDisplay(sealed, { kid, secretKey: attacker.secretKey }),
    /invalid tag|decrypt/i,
    "the attacker device opened a CEK addressed to the intended device",
  );
});

test("#77-C/2: a post-load RegExp.exec poison cannot reject or misroute a valid raw device key", () => {
  const device = x25519.keygen();
  const kid = "approver-1-device-1";
  const publicKeyHex = bytesToHex(device.publicKey);
  let fired = 0;

  const sealed = withPoison(RegExp.prototype, "exec",
    function () {
      fired++;
      return null;
    },
    () => {
      assert.equal(/^[0-9a-fA-F]{64}$/.test(publicKeyHex), false,
        "the RegExp.exec poison did not bite on its direct test() witness");
      assert.equal(fired, 1, "the RegExp.exec poison witness did not run exactly once");
      assert.deepEqual(decodeX25519PublicKey(publicKeyHex), device.publicKey,
        "the direct decoder misrouted a valid raw X25519 key through a live RegExp.exec slot");
      const result = sealEncryptedDisplay({
        tenant: "acme-tenant",
        holdId: "hold-regexp-exec",
        deferredReceiptHash: "sha256:" + "a".repeat(64),
        expiresAt: "2026-07-15T12:05:00.000Z",
        display: DANGEROUS,
        recipients: [{ kid, hpkePublicKey: publicKeyHex }],
      });
      assert.equal(fired, 1, "the sealer consulted the post-load RegExp.exec poison");
      return result;
    });

  assert.deepEqual(
    openEncryptedDisplay(sealed, { kid, secretKey: device.secretKey }),
    DANGEROUS,
    "capturing the native raw-key matcher broke the honest recipient path",
  );
});

test("#77-C/2: a recipients Proxy cannot self-restore global String after redirecting an index", () => {
  const intended = x25519.keygen();
  const attacker = x25519.keygen();
  const intendedKid = "intended-device";
  const source = [
    { kid: intendedKid, hpkePublicKey: bytesToHex(intended.publicKey) },
    { kid: "attacker-device", hpkePublicKey: bytesToHex(attacker.publicKey) },
  ];
  const realGlobal = globalThis;
  const stringDescriptor = Object.getOwnPropertyDescriptor(realGlobal, "String");
  assert.ok(stringDescriptor && "value" in stringDescriptor && stringDescriptor.configurable,
    "global String binding is unavailable for the attack witness");
  const realString = stringDescriptor.value as StringConstructor;
  let stringCalls = 0;
  const installRedirect = () => {
    Object.defineProperty(realGlobal, "String", {
      ...stringDescriptor,
      value: function poisonedString(value?: unknown) {
        stringCalls++;
        Object.defineProperty(realGlobal, "String", stringDescriptor);
        return value === 0 ? "1" : realString(value);
      },
    });
  };

  installRedirect();
  assert.equal(String(0), "1", "the self-restoring String redirect did not bite on its direct witness");
  assert.equal(globalThis.String, realString, "the String witness did not self-restore");
  const witnessCalls = stringCalls;

  let proxyCalls = 0;
  let redirectInstalled = false;
  const recipients = new Proxy(source, {
    getOwnPropertyDescriptor(target, key) {
      proxyCalls++;
      if (key === "length" && !redirectInstalled) {
        redirectInstalled = true;
        installRedirect();
      }
      return Reflect.getOwnPropertyDescriptor(target, key);
    },
  });
  let caught: unknown;
  try {
    try {
      sealEncryptedDisplay({
        tenant: "acme-tenant",
        holdId: "hold-self-restoring-string",
        deferredReceiptHash: "sha256:" + "a".repeat(64),
        expiresAt: "2026-07-15T12:05:00.000Z",
        display: DANGEROUS,
        recipients,
      });
    } catch (error) {
      caught = error;
    }
  } finally {
    Object.defineProperty(realGlobal, "String", stringDescriptor);
  }

  assert.ok(proxyCalls > 0, "the recipients Proxy did not bite on its direct descriptor path");
  assert.equal(stringCalls, witnessCalls,
    "recipient normalization invoked the attacker-selected live String binding");
  assert.match(String(caught), /runtime intrinsic integrity check failed: globalThis\.String/,
    "the sealer continued after a Proxy changed the global String binding");

  const honest = sealEncryptedDisplay({
    tenant: "acme-tenant",
    holdId: "hold-self-restoring-string",
    deferredReceiptHash: "sha256:" + "a".repeat(64),
    expiresAt: "2026-07-15T12:05:00.000Z",
    display: DANGEROUS,
    recipients: source,
  });
  assert.deepEqual(honest.recipients.map(({ kid }) => kid), [intendedKid, "attacker-device"]);
  assert.deepEqual(openEncryptedDisplay(honest, { kid: intendedKid, secretKey: intended.secretKey }), DANGEROUS,
    "closing the self-restoring index redirect broke the intended recipient path");
});

test("#77-C/2: a self-restoring TypedArray length getter cannot replace an SPKI recipient key", () => {
  const intended = x25519.keygen();
  const attacker = x25519.keygen();
  const kid = "intended-device";
  const intendedSpki = x25519SpkiBase64(intended.publicKey);
  const source = [{ kid, hpkePublicKey: intendedSpki }];
  const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype) as object;
  const lengthDescriptor = Object.getOwnPropertyDescriptor(typedArrayPrototype, "length");
  assert.ok(lengthDescriptor && typeof lengthDescriptor.get === "function" && lengthDescriptor.configurable,
    "%TypedArray%.prototype.length descriptor is unavailable for the attack witness");
  const realLength = lengthDescriptor.get;
  let lengthGetterCalls = 0;
  const installRedirect = () => {
    Object.defineProperty(typedArrayPrototype, "length", {
      ...lengthDescriptor,
      get(this: Uint8Array) {
        const length = Reflect.apply(realLength, this, []) as number;
        Object.defineProperty(typedArrayPrototype, "length", lengthDescriptor);
        if (length === 44) {
          lengthGetterCalls++;
          for (let i = 0; i < 32; i++) this[12 + i] = attacker.publicKey[i] as number;
        }
        return length;
      },
    });
  };

  installRedirect();
  const witness = base64ToBytes(intendedSpki);
  assert.equal(witness.length, 44, "the self-restoring length getter changed its direct witness length");
  assert.equal(lengthGetterCalls, 1, "the self-restoring length getter did not bite on its direct witness");
  assert.deepEqual(witness.slice(12), attacker.publicKey,
    "the direct witness could not replace the intended SPKI with the attacker key");

  let proxyCalls = 0;
  const recipients = new Proxy(source, {
    getOwnPropertyDescriptor(target, key) {
      proxyCalls++;
      if (key === "length") installRedirect();
      return Reflect.getOwnPropertyDescriptor(target, key);
    },
  });
  let caught: unknown;
  try {
    try {
      sealEncryptedDisplay({
        tenant: "acme-tenant",
        holdId: "hold-self-restoring-typedarray-length",
        deferredReceiptHash: "sha256:" + "a".repeat(64),
        expiresAt: "2026-07-15T12:05:00.000Z",
        display: DANGEROUS,
        recipients,
      });
    } catch (error) {
      caught = error;
    }
  } finally {
    Object.defineProperty(typedArrayPrototype, "length", lengthDescriptor);
  }

  assert.ok(proxyCalls > 0, "the recipients Proxy did not reach its descriptor path");
  assert.equal(lengthGetterCalls, 1,
    "recipient-key decoding invoked the attacker-selected TypedArray length getter");
  assert.match(String(caught), /runtime intrinsic integrity check failed: %TypedArray%\.prototype/,
    "the sealer accepted a post-entry TypedArray length mutation before generating the CEK");

  const honest = sealEncryptedDisplay({
    tenant: "acme-tenant",
    holdId: "hold-self-restoring-typedarray-length",
    deferredReceiptHash: "sha256:" + "a".repeat(64),
    expiresAt: "2026-07-15T12:05:00.000Z",
    display: DANGEROUS,
    recipients: source,
  });
  assert.deepEqual(openEncryptedDisplay(honest, { kid, secretKey: intended.secretKey }), DANGEROUS,
    "closing the self-restoring length redirect broke the intended device path");
  assert.throws(
    () => openEncryptedDisplay(honest, { kid, secretKey: attacker.secretKey }),
    /invalid tag|decrypt/i,
    "the attacker opened a CEK addressed to the intended SPKI",
  );
});

test("#77-C/1: a display Proxy cannot self-restore String.fromCodePoint after substituting text", () => {
  const device = x25519.keygen();
  const kid = "approver-1-device-1";
  const logicalDisplay = { title: "Wire 💣 to attacker" };
  const substitutedTitle = "Wire ✅ to attacker";
  const realGlobal = globalThis;
  const stringDescriptor = Object.getOwnPropertyDescriptor(realGlobal, "String");
  assert.ok(stringDescriptor && "value" in stringDescriptor && stringDescriptor.configurable,
    "global String binding is unavailable for the attack witness");
  const realString = stringDescriptor.value as StringConstructor;
  let fromCodePointCalls = 0;
  function PoisonedString(value?: unknown): string {
    return realString(value);
  }
  Object.defineProperty(PoisonedString, "fromCodePoint", {
    value() {
      fromCodePointCalls++;
      Object.defineProperty(realGlobal, "String", stringDescriptor);
      return "✅";
    },
  });
  const installPoison = () => {
    Object.defineProperty(realGlobal, "String", { ...stringDescriptor, value: PoisonedString });
  };

  installPoison();
  assert.equal(String.fromCodePoint(0x1f4a3), "✅",
    "the self-restoring String.fromCodePoint poison did not bite on its direct witness");
  assert.equal(globalThis.String, realString, "the String.fromCodePoint witness did not self-restore");
  const witnessCalls = fromCodePointCalls;

  let ownKeysCalls = 0;
  const display = new Proxy(logicalDisplay, {
    ownKeys(target) {
      ownKeysCalls++;
      installPoison();
      return Reflect.ownKeys(target);
    },
  });
  let caught: unknown;
  try {
    try {
      sealEncryptedDisplay({
        tenant: "acme-tenant",
        holdId: "hold-self-restoring-codepoint",
        deferredReceiptHash: "sha256:" + "a".repeat(64),
        expiresAt: "2026-07-15T12:05:00.000Z",
        display,
        recipients: [{ kid, hpkePublicKey: bytesToHex(device.publicKey) }],
      });
    } catch (error) {
      caught = error;
    }
  } finally {
    Object.defineProperty(realGlobal, "String", stringDescriptor);
  }

  assert.equal(ownKeysCalls, 1, "the display Proxy did not bite on canonicalization's ownKeys path");
  assert.equal(fromCodePointCalls, witnessCalls,
    "display canonicalization invoked the attacker-selected live String.fromCodePoint");
  assert.match(String(caught), /runtime intrinsic integrity check failed: globalThis\.String/,
    "the sealer continued after display canonicalization changed the global String binding");

  const honest = sealEncryptedDisplay({
    tenant: "acme-tenant",
    holdId: "hold-self-restoring-codepoint",
    deferredReceiptHash: "sha256:" + "a".repeat(64),
    expiresAt: "2026-07-15T12:05:00.000Z",
    display: logicalDisplay,
    recipients: [{ kid, hpkePublicKey: bytesToHex(device.publicKey) }],
  });
  const opened = openEncryptedDisplay(honest, { kid, secretKey: device.secretKey });
  assert.equal(opened["title"], logicalDisplay.title, "the honest encrypted display changed");
  assert.notEqual(opened["title"], substitutedTitle, "the authenticated human display was substituted");
});

// ────────────────────────────────────────────────────────────────────────────────────────────────
// ANTI-VACUITY — the honest path must keep working, or "refuse everything" would pass above.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("#77-C ANTI-VACUITY: an ordinary seal→open round-trip returns the EXACT sealed display", () => {
  const f = fixture();
  assert.deepEqual(f.open(), DANGEROUS, "the ordinary round trip does not return the sealed display");
});

test("#77-C ANTI-VACUITY: browser/webview cross-realm recipient arrays seal and open safely", () => {
  const device = x25519.keygen();
  const kid = "cross-realm-device";
  const foreignSealRecipients = runInNewContext("JSON.parse(serialized)", {
    serialized: JSON.stringify([{ kid, hpkePublicKey: bytesToHex(device.publicKey) }]),
  }) as Array<{ kid: string; hpkePublicKey: string }>;
  assert.equal(Array.isArray(foreignSealRecipients), true, "the seal fixture is not an Array brand");
  assert.notEqual(Object.getPrototypeOf(foreignSealRecipients), Array.prototype,
    "the seal fixture unexpectedly came from the current realm");

  const sealed = sealEncryptedDisplay({
    tenant: "acme-tenant",
    holdId: "hold-cross-realm",
    deferredReceiptHash: "sha256:" + "a".repeat(64),
    expiresAt: "2026-07-15T12:05:00.000Z",
    display: DANGEROUS,
    recipients: foreignSealRecipients,
  });
  const foreignOpenRecipients = runInNewContext("JSON.parse(serialized)", {
    serialized: JSON.stringify(sealed.recipients),
  }) as typeof sealed.recipients;
  const foreignSecretKey = runInNewContext("Uint8Array.from(bytes)", {
    bytes: Array.from(device.secretKey),
  }) as Uint8Array;
  assert.equal(Array.isArray(foreignOpenRecipients), true, "the open fixture is not an Array brand");
  assert.notEqual(Object.getPrototypeOf(foreignOpenRecipients), Array.prototype,
    "the open fixture unexpectedly came from the current realm");
  assert.notEqual(Object.getPrototypeOf(foreignSecretKey), Uint8Array.prototype,
    "the secret-key fixture unexpectedly came from the current realm");

  assert.deepEqual(
    openEncryptedDisplay({ ...sealed, recipients: foreignOpenRecipients }, { kid, secretKey: foreignSecretKey }),
    DANGEROUS,
    "cross-realm normalization changed the authenticated display",
  );
});

test("#77-C ANTI-VACUITY: the AEAD still rejects a tampered ciphertext and a wrong key", () => {
  const f = fixture();
  const tampered = structuredClone(f.ed) as typeof f.ed;
  tampered.payload.ciphertext = tampered.payload.ciphertext.slice(0, -4) + "AAAA";
  assert.throws(() => openEncryptedDisplay(tampered, { kid: f.kid, secretKey: f.device.secretKey }),
    /invalid tag|decrypt/i, "a tampered ciphertext was accepted");

  const stranger = x25519.keygen();
  assert.throws(() => openEncryptedDisplay(f.ed, { kid: f.kid, secretKey: stranger.secretKey }),
    /invalid tag|decrypt/i, "a wrong device key opened the display");
});

test("#77-C ANTI-VACUITY: the AAD still binds tenant, holdId, deferredReceiptHash and expiresAt", () => {
  // These four are what the AAD actually covers — measured. The binding audit's OPEN items
  // (recipient set, projection identity, challenge/nonce) are recorded in task #80 and PROGRESS.md
  // as an owner decision, NOT silently treated as bound here.
  for (const mutate of [
    (e: Record<string, unknown>) => { e["tenant"] = "other-tenant"; },
    (e: Record<string, unknown>) => { e["holdId"] = "hold-other"; },
    (e: Record<string, unknown>) => { e["deferredReceiptHash"] = "sha256:" + "b".repeat(64); },
    (e: Record<string, unknown>) => { e["expiresAt"] = "2099-01-01T00:00:00.000Z"; },
  ]) {
    const f = fixture();
    const t = structuredClone(f.ed) as unknown as Record<string, unknown>;
    mutate(t);
    assert.throws(() => openEncryptedDisplay(t, { kid: f.kid, secretKey: f.device.secretKey }),
      /aadHash|invalid tag/i, "an AAD-bound field was altered without detection");
  }
});
