#!/usr/bin/env node

import { createHash } from "node:crypto";
import { open, readFile, readdir, realpath, rename, unlink } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

// ── CAPTURED BUILTINS ───────────────────────────────────────────────────────────────────────────
// A named import from a Node builtin is a LIVE BINDING, and `syncBuiltinESMExports()` re-points it
// from the CommonJS object. MEASURED: replacing `fs/promises` open and readdir and then calling
// syncBuiltinESMExports redirected 194 opens and 8 readdirs to clean copies and the attestation
// returned evidence=3 with the malicious file still on disk. Replacing only `path.resolve` redirected
// all three package roots (3 redirects, false pass); replacing only `path.join` redirected a single
// changed file's read (1 redirect, false pass) — each is independently sufficient, so each is
// captured and each is proven separately. Nothing below calls an imported binding at runtime.
const fsOpen = open;
const fsReadFile = readFile;
const fsReaddir = readdir;
const fsRealpath = realpath;
const fsRename = rename;
const fsUnlink = unlink;
const pathJoin = join;
const pathResolve = resolve;
const pathDirname = dirname;
const pathSep = sep;
const cryptoCreateHash = createHash;
const urlFileURLToPath = fileURLToPath;
const capturedFsConstants = fsConstants;
const { O_RDONLY, O_DIRECTORY } = capturedFsConstants;
const SCRIPT_DIR = pathDirname(urlFileURLToPath(import.meta.url));

// ── CAPTURED INTRINSICS FOR THE ATTESTATION PATH ────────────────────────────────────────────────
// The evidence this file produces is only worth what its own reads are worth, and `handle.stat()` /
// `handle.readFile()` are LIVE prototype dispatch. MEASURED: with the module imported first, then
// `FileHandle.prototype.readFile` replaced so that one held inode returns the original clean bytes,
// `attestHardenedDependencyTrees` returned PASS with the exact 33/72/60 counts and all three expected
// digests while the victim file on disk said "MALICIOUS BUT HIDDEN FROM ATTESTATION". A digest
// function is just as fatal: a replaced `Hash.prototype.digest` can return the expected hash for any
// bytes at all. Everything the attestation depends on is therefore bound at module load and invoked
// through a captured `Reflect.apply`, exactly as the runtime-integrity module does for signing.
//
// SCOPE, stated rather than implied: this defends against POST-load replacement. A poison already in
// place when this module is evaluated is captured into these bindings — the same bound the rest of
// this package documents.
const reflectApply = Reflect.apply;
const objectGetPrototypeOf = Object.getPrototypeOf;
const arrayPush = Array.prototype.push;
const arraySort = Array.prototype.sort;
const arrayJoin = Array.prototype.join;
const stringIncludes = String.prototype.includes;
const bufferFrom = Buffer.from;
const bufferCompare = Buffer.compare;
// `split` resolves a package NAME into path segments and `startsWith` is the containment check that
// keeps resolution inside node_modules. MEASURED: replacing them post-load redirected all three
// package resolutions to a clean copy outside node_modules while the real trees held MALICIOUS.txt,
// and the attestation returned every exact expected digest.
const stringSplit = String.prototype.split;
const stringStartsWith = String.prototype.startsWith;
// `Object.freeze` is a LIVE lookup, and the attestation's return value passes through it. MEASURED:
// patching it to hand back the pinned expectations in sequence made the attestation return normally
// with the exact 33/72/60 evidence while every real tree contained only MALICIOUS.txt. The clock the
// expiry gate reads is the same class of dependency.
const objectFreeze = Object.freeze;
const numberIsFinite = Number.isFinite;
const dateParse = Date.parse;
const dateNow = Date.now;

const bootstrapHandle = await fsOpen(urlFileURLToPath(import.meta.url), O_RDONLY);
const fileHandlePrototype = objectGetPrototypeOf(bootstrapHandle);
const handleStat = fileHandlePrototype.stat;
const handleReadFile = fileHandlePrototype.readFile;
// Stats answers "is this a file or a directory?", which is the question the whole traversal turns
// on, and `isFile`/`isDirectory` are shared prototype methods like any other.
const statsPrototype = objectGetPrototypeOf(await reflectApply(handleStat, bootstrapHandle, []));
const statsIsFile = statsPrototype.isFile;
const statsIsDirectory = statsPrototype.isDirectory;
await bootstrapHandle.close();
if (typeof statsIsFile !== "function" || typeof statsIsDirectory !== "function") {
  throw new Error("dependency hardening bootstrap failed: Stats intrinsics are unavailable");
}
// `stat` and `readFile` live on FileHandle.prototype — shared, replaceable, and the exact slots the
// reproduction used. `close` is an OWN property of each handle, so a prototype poison is shadowed by
// the instance and there is no shared slot to capture; it is called directly and deliberately.
if (typeof handleStat !== "function" || typeof handleReadFile !== "function") {
  throw new Error("dependency hardening bootstrap failed: FileHandle intrinsics are unavailable");
}

const hashPrototype = objectGetPrototypeOf(cryptoCreateHash("sha256"));
const hashUpdate = hashPrototype.update;
const hashDigest = hashPrototype.digest;
if (typeof hashUpdate !== "function" || typeof hashDigest !== "function") {
  throw new Error("dependency hardening bootstrap failed: hash intrinsics are unavailable");
}
const DEFAULT_PACKAGE_ROOT = pathResolve(SCRIPT_DIR, "..");

export const HARDENING_POLICY = Object.freeze({
  id: "NOA-NOBLE-POSTLOAD-STATE-ISOLATION-2026-08-24",
  owner: "NOA Trust security maintainers",
  reviewBy: "2026-11-24",
  expiresAt: "2026-11-25T00:00:00.000Z",
  replacementCondition:
    "Remove only after supported upstream releases isolate the same state and every retained-reference regression passes without this patch.",
});

const lines = (...value) => `${value.join("\n")}\n`;

const PATCHES = Object.freeze([
  {
    packageName: "@noble/ciphers",
    version: "2.3.0",
    relativePath: "_arx.js",
    beforeSha256: "bcd2c8e9d3a9252022c74185340d69d724d2c2eed191f5599a2cec5005507d93",
    afterSha256: "85f1508f3566bbb9b3304c30e42c93b47fd8bb8535e07453f69883f5fb421105",
    replacements: [
      {
        before: lines(
          "            toClean.push((k = copyBytes(key)));",
          "            sigma = sigma32_32;",
          "        }",
          "        else if (l === 16 && allowShortKeys) {",
          "            k = new Uint8Array(32);",
          "            k.set(key);",
          "            k.set(key, 16);",
          "            sigma = sigma16_32;",
          "            toClean.push(k);",
        ),
        after: lines(
          "            toClean.push((k = copyBytes(key)));",
          "            // Do not pass the module-private constant to an exported/custom core callback.",
          "            // Allocate through the native constructor captured at module load, then copy by",
          "            // index. A post-load construct Proxy must never receive the private source table.",
          "            toClean.push((sigma = copySigma(sigma32_32)));",
          "        }",
          "        else if (l === 16 && allowShortKeys) {",
          "            k = new Uint8Array(32);",
          "            k.set(key);",
          "            k.set(key, 16);",
          "            toClean.push((sigma = copySigma(sigma16_32)));",
          "            toClean.push(k);",
        ),
      },
      {
        before: lines(
          "const sigma32_32 = /* @__PURE__ */ (() => swap32IfBE(u32(encodeStr('expand 32-byte k'))))();",
        ),
        after: lines(
          "const sigma32_32 = /* @__PURE__ */ (() => swap32IfBE(u32(encodeStr('expand 32-byte k'))))();",
          "// Capture the native constructor before any supported post-load adversary can replace it.",
          "// Never give a live constructor the module-private sigma table as a source argument.",
          "const Uint32ArrayCtor = Uint32Array;",
          "const copySigma = (source) => {",
          "    const copy = new Uint32ArrayCtor(4);",
          "    copy[0] = source[0];",
          "    copy[1] = source[1];",
          "    copy[2] = source[2];",
          "    copy[3] = source[3];",
          "    return copy;",
          "};",
        ),
      },
    ],
  },
  {
    packageName: "@noble/ciphers",
    version: "2.3.0",
    relativePath: "chacha.js",
    beforeSha256: "5f1c00575e227b75163f4bac50b79442dec50ee3047c46c18887808ba8af0a69",
    afterSha256: "a4f95bc4258457f7704859c0c87e99151b0b4a4d21fd64cc923774cefdbf48b5",
    replacements: [
      {
        before: lines(
          "// RFC 8439 §2.8.1 pad16(x): shared zero block for AAD/ciphertext padding.",
          "const ZEROS16 = /* @__PURE__ */ new Uint8Array(16);",
          "// RFC 8439 §2.8 / §2.8.1: aligned inputs add nothing, otherwise append 16-(len%16) zero bytes.",
          "const updatePadded = (h, msg) => {",
          "    h.update(msg);",
          "    const leftover = msg.length % 16;",
          "    if (leftover)",
          "        h.update(ZEROS16.subarray(leftover));",
          "};",
          "// RFC 8439 §2.6.1 poly1305_key_gen returns `block[0..31]`, so AEAD key",
          "// generation only needs 32 zero bytes.",
          "const ZEROS32 = /* @__PURE__ */ new Uint8Array(32);",
        ),
        after: lines(
          "// RFC 8439 §2.8 / §2.8.1: aligned inputs add nothing, otherwise append 16-(len%16) zero bytes.",
          "const updatePadded = (h, msg) => {",
          "    h.update(msg);",
          "    const leftover = msg.length % 16;",
          "    if (leftover)",
          "        // Per-call padding prevents a retained update() argument from corrupting later AEAD calls.",
          "        h.update(new Uint8Array(16 - leftover));",
          "};",
        ),
      },
      {
        before: "    const authKey = fn(key, nonce, ZEROS32);",
        after: lines(
          "    // RFC 8439 §2.6.1 poly1305_key_gen consumes 32 zero bytes. Keep the input",
          "    // invocation-local because `_poly1305_aead` accepts an exported/custom stream callback.",
          "    const authKey = fn(key, nonce, new Uint8Array(32));",
        ).trimEnd(),
      },
    ],
  },
  {
    packageName: "@noble/curves",
    version: "2.3.0",
    relativePath: "abstract/montgomery.js",
    beforeSha256: "cdafa8816dad5a24475ec51952c5f71fdd5d1b46880ab982694c4f8ff605fc46",
    afterSha256: "0bd13de0498f73178e1286bbfaadc404c2fa90624abd669fa938a277d36d0600",
    replacements: [
      {
        before: "    const lowOrderU = new Set(is25519",
        after: lines(
          "    // Primitive BigInt entries in a frozen array cannot be added/removed after module load.",
          "    // Use direct indexed comparisons below so no replaceable collection method receives it.",
          "    const lowOrderU = Object.freeze(is25519",
        ).trimEnd(),
      },
      {
        before: lines(
          "        const pointU = decodeU(u);",
          "        if (lowOrderU.has(pointU))",
          "            throw new Error('invalid private or public key received');",
        ),
        after: lines(
          "        const pointU = decodeU(u);",
          "        let isLowOrder = false;",
          "        for (let i = 0; i < lowOrderU.length; i++) {",
          "            if (lowOrderU[i] === pointU) {",
          "                isLowOrder = true;",
          "                break;",
          "            }",
          "        }",
          "        if (isLowOrder)",
          "            throw new Error('invalid private or public key received');",
        ),
      },
    ],
  },
  {
    packageName: "@noble/curves",
    version: "2.3.0",
    relativePath: "abstract/curve.js",
    beforeSha256: "dbaeee3b41ff47efb76b78e14170fe4dda7c7ecdc387c402f16c5118e0bac356",
    afterSha256: "99e61dab536e78d3926de0f7053f6108c81e2909b170b2eea5071d901fc29827",
    replacements: [
      {
        before: lines(
          "    runCT(point, n, bits, transform) {",
          "        const W = getWindowSize(point);",
        ),
        after: lines(
          "    runCT(point, n, bits, transform, forceFixedWindow = false) {",
          "        if (forceFixedWindow)",
          "            return this.fixedWindowCT(point, n, bits);",
          "        const W = getWindowSize(point);",
        ),
      },
      {
        before: lines(
          "    mulCT(point, scalar, transform) {",
          "        this.validateMulInput(point, scalar);",
          "        return this.runCT(point, scalar, this.bits, transform);",
          "    }",
        ),
        after: lines(
          "    mulCT(point, scalar, transform, forceFixedWindow = false) {",
          "        this.validateMulInput(point, scalar);",
          "        return this.runCT(point, scalar, this.bits, transform, forceFixedWindow);",
          "    }",
        ),
      },
      {
        before: "    mulCTBlinded(point, scalar, transform) {",
        after: "    mulCTBlinded(point, scalar, transform, forceFixedWindow = false) {",
      },
      {
        before: lines(
          "        return this.runCT(point, n, bits, transform);",
          "    }",
          "    /**",
        ),
        after: lines(
          "        return this.runCT(point, n, bits, transform, forceFixedWindow);",
          "    }",
          "    /**",
        ),
      },
      {
        before: lines(
          "    mulSecret(point, scalar, cofactor, transform) {",
          "        return this.shouldBlind(point, cofactor)",
        ),
        after: lines(
          "    /** Secret-scalar path with invocation-local state and no window-map or precompute-cache read. */",
          "    mulSecretIsolated(point, scalar, cofactor, baseCanBeBlinded) {",
          "        if (typeof baseCanBeBlinded !== 'boolean')",
          "            throw new TypeError('baseCanBeBlinded expected boolean');",
          "        const useBlinding = this.randomBytes !== undefined &&",
          "            (cofactor === _1n || (point === this.BASE && baseCanBeBlinded));",
          "        return useBlinding",
          "            ? this.mulCTBlinded(point, scalar, undefined, true)",
          "            : this.mulCT(point, scalar, undefined, true);",
          "    }",
          "    mulSecret(point, scalar, cofactor, transform) {",
          "        return this.shouldBlind(point, cofactor)",
        ),
      },
    ],
  },
  {
    packageName: "@noble/curves",
    version: "2.3.0",
    relativePath: "abstract/edwards.js",
    beforeSha256: "c97067225e3626227cdd944b1efd6375cdd6e847812beb7fcdef7e23488edb00",
    afterSha256: "5e53148d5682860e20fa4158f59f3d3fc714f5c3ec3b045a3c66e26dcc41fb84",
    replacements: [
      {
        before: "            const { p, f } = wnaf.mulSecret(this, scalar, cofactor, normalize);",
        after: lines(
          "            // Secret multiplication must not reuse state reachable through earlier public calls.",
          "            // This fresh instance takes the fixed-window isolated path and becomes unreachable here.",
          "            const secretMultiplier = new ScalarMultiplier(Point, randomBytes);",
          "            const { p, f } = secretMultiplier.mulSecretIsolated(this, scalar, cofactor, baseCanBeBlinded);",
        ).trimEnd(),
      },
      {
        before: lines(
          "    const wnaf = new ScalarMultiplier(Point, randomBytes);",
          "    // Enable W=6 wNAF precomputes. Slows down first publicKey computation.",
        ),
        after: lines(
          "    const wnaf = new ScalarMultiplier(Point, randomBytes);",
          "    // Establish once, before the Point constructor is published, whether scalar blinding preserves BASE.",
          "    // The immutable boolean is passed to invocation-local secret multipliers; no retained map/cache decides it.",
          "    const baseCanBeBlinded = cofactor === _1n || wnaf.mulUnsafe(Point.BASE, Point.Fn.ORDER).is0();",
          "    // Enable W=6 wNAF precomputes. Slows down first publicKey computation.",
        ),
      },
    ],
  },
  {
    packageName: "@noble/hashes",
    version: "2.3.0",
    relativePath: "sha2.js",
    beforeSha256: "471746bba6ec4c6238ca41358d1d3b40b6ff31cf3363f0b4d550c649c1a8e83b",
    afterSha256: "cd379e847906f394a9843f9a47fd2015e4a54772c7850e0d1364a45a1d5a6d7b",
    replacements: [
      {
        before: lines(
          'import { Chi, HashMD, Maj, SHA224_IV, SHA256_IV, SHA384_IV, SHA512_IV } from "./_md.js";',
          'import * as u64 from "./_u64.js";',
          'import { clean, createHasher, oidNist, rotr } from "./utils.js";',
        ),
        after: lines(
          'import { Chi, HashMD, Maj, SHA224_IV, SHA256_IV, SHA384_IV, SHA512_IV } from "./_md.js";',
          'import * as u64 from "./_u64.js";',
          'import { clean, createHasher, oidNist, rotr } from "./utils.js";',
          "// Exported IV tables are mutable dependency API. Freeze primitive module-load copies so",
          "// even a retained constructor argument cannot change a later SHA-2 instance.",
          "const SHA224_IV_PRIVATE = /* @__PURE__ */ Object.freeze(Array.from(SHA224_IV));",
          "const SHA256_IV_PRIVATE = /* @__PURE__ */ Object.freeze(Array.from(SHA256_IV));",
          "const SHA384_IV_PRIVATE = /* @__PURE__ */ Object.freeze(Array.from(SHA384_IV));",
          "const SHA512_IV_PRIVATE = /* @__PURE__ */ Object.freeze(Array.from(SHA512_IV));",
        ),
      },
      {
        before: lines(
          "/** Reusable SHA-224 / SHA-256 message schedule buffer `W_t` from RFC 6234 §6.2 step 1. */",
          "const SHA256_W = /* @__PURE__ */ new Uint32Array(64);",
        ),
        after: "",
      },
      {
        before: lines("    G = 0;", "    H = 0;", "    constructor(outputLen, IV) {"),
        after: lines(
          "    G = 0;",
          "    H = 0;",
          "    /** Instance-local RFC 6234 §6.2 message schedule. */",
          "    W = new Uint32Array(64);",
          "    constructor(outputLen, IV) {",
        ),
      },
      {
        before: "        super(32, SHA256_IV);",
        after: "        super(32, SHA256_IV_PRIVATE);",
      },
      {
        before: "        super(28, SHA224_IV);",
        after: "        super(28, SHA224_IV_PRIVATE);",
      },
      {
        before: "        super(64, SHA512_IV);",
        after: "        super(64, SHA512_IV_PRIVATE);",
      },
      {
        before: "        super(48, SHA384_IV);",
        after: "        super(48, SHA384_IV_PRIVATE);",
      },
      {
        before: lines(
          "    process(view, offset) {",
          "        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array",
          "        for (let i = 0; i < 16; i++, offset += 4)",
          "            SHA256_W[i] = view.getUint32(offset, false);",
          "        for (let i = 16; i < 64; i++) {",
          "            const W15 = SHA256_W[i - 15];",
          "            const W2 = SHA256_W[i - 2];",
          "            const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ (W15 >>> 3);",
          "            const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ (W2 >>> 10);",
          "            SHA256_W[i] = (s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16]) | 0;",
          "        }",
        ),
        after: lines(
          "    process(view, offset) {",
          "        const W = this.W;",
          "        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array",
          "        for (let i = 0; i < 16; i++, offset += 4)",
          "            W[i] = view.getUint32(offset, false);",
          "        for (let i = 16; i < 64; i++) {",
          "            const W15 = W[i - 15];",
          "            const W2 = W[i - 2];",
          "            const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ (W15 >>> 3);",
          "            const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ (W2 >>> 10);",
          "            W[i] = (s1 + W[i - 7] + s0 + W[i - 16]) | 0;",
          "        }",
        ),
      },
      {
        before: lines(
          "            const T1 = (H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i]) | 0;",
          "            const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);",
        ),
        after: lines(
          "            const T1 = (H + sigma1 + Chi(E, F, G) + SHA256_K[i] + W[i]) | 0;",
          "            const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);",
        ),
      },
      {
        before: lines(
          "    roundClean() {",
          "        clean(SHA256_W);",
          "    }",
          "    destroy() {",
          "        // HashMD callers route post-destroy usability through `destroyed`; zeroizing alone still leaves",
          "        // update()/digest() callable on reused instances.",
          "        this.destroyed = true;",
          "        this.set(0, 0, 0, 0, 0, 0, 0, 0);",
          "        clean(this.buffer);",
        ),
        after: lines(
          "    roundClean() {",
          "        clean(this.W);",
          "    }",
          "    destroy() {",
          "        // HashMD callers route post-destroy usability through `destroyed`; zeroizing alone still leaves",
          "        // update()/digest() callable on reused instances.",
          "        this.destroyed = true;",
          "        this.set(0, 0, 0, 0, 0, 0, 0, 0);",
          "        clean(this.buffer, this.W);",
        ),
      },
      {
        before: lines(
          "// Reusable high-half schedule buffer for the RFC 6234 §6.4 64-bit `W_t` words.",
          "const SHA512_W_H = /* @__PURE__ */ new Uint32Array(80);",
          "// Reusable low-half schedule buffer for the RFC 6234 §6.4 64-bit `W_t` words.",
          "const SHA512_W_L = /* @__PURE__ */ new Uint32Array(80);",
        ),
        after: "",
      },
      {
        before: lines("    Hh = 0;", "    Hl = 0;", "    constructor(outputLen, IV) {"),
        after: lines(
          "    Hh = 0;",
          "    Hl = 0;",
          "    /** Instance-local high/low halves of the RFC 6234 §6.4 message schedule. */",
          "    WH = new Uint32Array(80);",
          "    WL = new Uint32Array(80);",
          "    constructor(outputLen, IV) {",
        ),
      },
      {
        before: lines(
          "    process(view, offset) {",
          "        // Extend the first 16 words into the remaining 64 words w[16..79] of the message schedule array",
          "        for (let i = 0; i < 16; i++, offset += 4) {",
          "            SHA512_W_H[i] = view.getUint32(offset);",
          "            SHA512_W_L[i] = view.getUint32((offset += 4));",
          "        }",
        ),
        after: lines(
          "    process(view, offset) {",
          "        const WH = this.WH;",
          "        const WL = this.WL;",
          "        // Extend the first 16 words into the remaining 64 words w[16..79] of the message schedule array",
          "        for (let i = 0; i < 16; i++, offset += 4) {",
          "            WH[i] = view.getUint32(offset);",
          "            WL[i] = view.getUint32((offset += 4));",
          "        }",
        ),
      },
      {
        before: lines(
          "            const W15h = SHA512_W_H[i - 15] | 0;",
          "            const W15l = SHA512_W_L[i - 15] | 0;",
        ),
        after: lines(
          "            const W15h = WH[i - 15] | 0;",
          "            const W15l = WL[i - 15] | 0;",
        ),
      },
      {
        before: lines(
          "            const W2h = SHA512_W_H[i - 2] | 0;",
          "            const W2l = SHA512_W_L[i - 2] | 0;",
        ),
        after: lines(
          "            const W2h = WH[i - 2] | 0;",
          "            const W2l = WL[i - 2] | 0;",
        ),
      },
      {
        before: lines(
          "            const SUMl = u64.add4L(s0l, s1l, SHA512_W_L[i - 7], SHA512_W_L[i - 16]);",
          "            const SUMh = u64.add4H(SUMl, s0h, s1h, SHA512_W_H[i - 7], SHA512_W_H[i - 16]);",
          "            SHA512_W_H[i] = SUMh | 0;",
          "            SHA512_W_L[i] = SUMl | 0;",
        ),
        after: lines(
          "            const SUMl = u64.add4L(s0l, s1l, WL[i - 7], WL[i - 16]);",
          "            const SUMh = u64.add4H(SUMl, s0h, s1h, WH[i - 7], WH[i - 16]);",
          "            WH[i] = SUMh | 0;",
          "            WL[i] = SUMl | 0;",
        ),
      },
      {
        before: lines(
          "            const T1ll = u64.add5L(Hl, sigma1l, CHIl, SHA512_Kl[i], SHA512_W_L[i]);",
          "            const T1h = u64.add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh[i], SHA512_W_H[i]);",
        ),
        after: lines(
          "            const T1ll = u64.add5L(Hl, sigma1l, CHIl, SHA512_Kl[i], WL[i]);",
          "            const T1h = u64.add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh[i], WH[i]);",
        ),
      },
      {
        before: lines(
          "    roundClean() {",
          "        clean(SHA512_W_H, SHA512_W_L);",
          "    }",
          "    destroy() {",
          "        // HashMD callers route post-destroy usability through `destroyed`; zeroizing alone still leaves",
          "        // update()/digest() callable on reused instances.",
          "        this.destroyed = true;",
          "        clean(this.buffer);",
        ),
        after: lines(
          "    roundClean() {",
          "        clean(this.WH, this.WL);",
          "    }",
          "    destroy() {",
          "        // HashMD callers route post-destroy usability through `destroyed`; zeroizing alone still leaves",
          "        // update()/digest() callable on reused instances.",
          "        this.destroyed = true;",
          "        clean(this.buffer, this.WH, this.WL);",
        ),
      },
      {
        before: "const T224_IV = /* @__PURE__ */ Uint32Array.from([",
        after: "const T224_IV = /* @__PURE__ */ Object.freeze([",
      },
      {
        before: "const T256_IV = /* @__PURE__ */ Uint32Array.from([",
        after: "const T256_IV = /* @__PURE__ */ Object.freeze([",
      },
    ],
  },
  {
    packageName: "@noble/hashes",
    version: "2.3.0",
    relativePath: "hkdf.js",
    beforeSha256: "ccb942a8008f974018965eeb1e33b8f4739bf767c6f95f2ceb06f5873a302f67",
    afterSha256: "cde45967efb5501a430e37cc9f448d599af1606ccaf44f7bc529d96e41976d40",
    replacements: [
      {
        before: lines(
          "// Shared mutable scratch byte for the RFC 5869 block counter `N`.",
          "// Safe to reuse because `expand()` is synchronous and resets it with `clean(...)` before returning.",
          "const HKDF_COUNTER = /* @__PURE__ */ Uint8Array.of(0);",
          "// Shared RFC 5869 empty string for both `info === undefined` and the first-block `T(0)` input.",
          "const EMPTY_BUFFER = /* @__PURE__ */ Uint8Array.of();",
        ),
        after: "",
      },
      {
        before: "        info = EMPTY_BUFFER;",
        after: "        info = new Uint8Array();",
      },
      {
        before: lines(
          "    // Driving them directly also skips `_HMAC.digestInto`'s per-digest destroy.",
          "    const T = _recycled ? prk : new Uint8Array(olen);",
          "    // Full hkdf() donates one destroyed extract hash; standalone creates one alternating worker.",
        ),
        after: lines(
          "    // Driving them directly also skips `_HMAC.digestInto`'s per-digest destroy.",
          "    const T = _recycled ? prk : new Uint8Array(olen);",
          "    // Invocation-local RFC 5869 block counter. A retained hash update argument",
          "    // must not allow corruption or detachment of later expand() operations.",
          "    const counterByte = new Uint8Array(1);",
          "    // Full hkdf() donates one destroyed extract hash; standalone creates one alternating worker.",
        ),
      },
      { before: "        HKDF_COUNTER[0] = counter + 1;", after: "        counterByte[0] = counter + 1;" },
      {
        before: "        iWork.update(info).update(HKDF_COUNTER).digestInto(T);",
        after: "        iWork.update(info).update(counterByte).digestInto(T);",
      },
      {
        before: "    HKDF_COUNTER[0] = blocks; // Final block consumes them; retain worker for cleanup.",
        after: "    counterByte[0] = blocks; // Final block consumes them; retain worker for cleanup.",
      },
      {
        before: "    iHash.update(info).update(HKDF_COUNTER).digestInto(T);",
        after: "    iHash.update(info).update(counterByte).digestInto(T);",
      },
      { before: "    clean(HKDF_COUNTER);", after: "    clean(counterByte);" },
    ],
  },
]);

export const HARDENED_PACKAGE_NAMES = Object.freeze(
  [...new Set(PATCHES.map((patch) => patch.packageName))].sort(),
);
export const HARDENED_ARTIFACT_PATHS = Object.freeze(
  PATCHES.map((patch) => `node_modules/${patch.packageName}/${patch.relativePath}`).sort(),
);

/**
 * Exact aggregate manifests of the complete npm-installed package trees after the seven reviewed
 * transforms above. The digest commits to every relative path and every file byte, not merely the
 * files we patch. These values were derived from an integrity-pinned clean `npm ci --omit=dev`, the
 * exact transformer, and an independently extracted `npm pack` artifact; the test suite repeats the
 * extracted-artifact half. Adding, removing, or changing any bundled dependency file is a refusal.
 */
export const HARDENED_PACKAGE_TREES = Object.freeze([
  Object.freeze({ packageName: "@noble/ciphers", version: "2.3.0", files: 33, sha256: "4c23ace768352be3c371d5e8524008454ba8a3ecf62c73b7d0de9ab86617bda5" }),
  Object.freeze({ packageName: "@noble/curves", version: "2.3.0", files: 72, sha256: "2240ae0d81d8565df07d6fa8996ad73803e5efa45186f27295e2faa517712609" }),
  Object.freeze({ packageName: "@noble/hashes", version: "2.3.0", files: 60, sha256: "b61471402c6a0675d64edd476c097dfaec0e95fe60f7bc95a3b765a9a1d6bcdb" }),
]);

const sha256 = (value) => reflectApply(
  hashDigest,
  reflectApply(hashUpdate, cryptoCreateHash("sha256"), [value]),
  ["hex"],
);

const bytewiseNameOrder = (left, right) => reflectApply(bufferCompare, Buffer, [
  reflectApply(bufferFrom, Buffer, [left.name]),
  reflectApply(bufferFrom, Buffer, [right.name]),
]);

/**
 * ── PLATFORM SCOPE OF THE TWO REQUIRED OPEN FLAGS ────────────────────────────────────────────────
 * Both flags below are POSIX open flags, and both are REQUIRED rather than optional: where the
 * constant is missing or zero the attestation refuses instead of degrading. That refusal is the
 * control, so it is stated here rather than softened.
 *
 * The consequence, exactly: this file is `postinstall` for `noa-signer` and is listed in its `files`,
 * so on any platform that does not provide these constants the attestation would REFUSE and the
 * install would fail rather than produce an unproven tree. VERIFIED on this repository: every
 * workflow that runs it is `ubuntu-latest`, and `noa-signer` is `private: true`, so it is never
 * published and never installed anywhere but here. [UNVERIFIED LOCALLY: Node documents which
 * `fs.constants.O_*` are unavailable on Windows; no Windows host was available to measure it, and
 * `@types/node` carries no availability note for these two.]
 *
 * The word "portable" in `noa-signer`'s package description is about the SIGNING CORE it ships in
 * `dist/src` — that code imports nothing from this file and touches no filesystem constant. This is
 * a release-gate tool, not part of the portable surface, and the two claims do not meet.
 */

/**
 * The open flag that refuses to traverse a symlink — or a refusal.
 *
 * This was `fsConstants.O_NOFOLLOW ?? 0`. Zero is a NO-OP flag: on a platform without the constant
 * that expression silently produced an ordinary following open while the surrounding code, and the
 * commit message describing it, both claimed symlink safety. A control that quietly becomes its own
 * absence is worse than no control, so an attestation that cannot prove it did not follow a link
 * refuses to be performed at all. The parameter exists so the refusal itself is testable.
 */
export function symlinkSafeOpenFlag(constants = capturedFsConstants) {
  const flag = constants.O_NOFOLLOW;
  if (typeof flag !== "number" || flag === 0) {
    throw new Error(
      "O_NOFOLLOW is unavailable on this platform, so a read cannot be proven not to have followed a " +
      "symbolic link; the dependency-tree attestation refuses rather than silently following one",
    );
  }
  return flag;
}

/**
 * The open flag that refuses to WAIT — or a refusal.
 *
 * A blocking `O_RDONLY` on a FIFO waits for a writer that may never come. MEASURED: a dependency tree
 * containing one made the attestation print its first line and then hang until it was killed at six
 * seconds. An attestation that can be made to hang forever by a file type is a denial of service on
 * the release gate, so the flag is required exactly as `O_NOFOLLOW` is: absent, the attestation
 * refuses rather than risk it. The FIFO itself is then rejected by `fstat` as a non-regular entry.
 */
export function nonBlockingOpenFlag(constants = capturedFsConstants) {
  const flag = constants.O_NONBLOCK;
  if (typeof flag !== "number" || flag === 0) {
    throw new Error(
      "O_NONBLOCK is unavailable on this platform, so a dependency tree containing a FIFO would block " +
      "the attestation indefinitely; it refuses rather than hang",
    );
  }
  return flag;
}

/**
 * Open one path once and answer everything from that descriptor: what it is, and what it contains.
 *
 * The earlier shape `lstat`-ed a path and then read the same path again, so every attestation had a
 * window in which the object checked and the object hashed could differ — CodeQL's js/file-system-race,
 * and exactly what a symlink swap needs. There is no `lstat` here at all: `O_NOFOLLOW` refuses a link
 * at open time and `fstat` describes the object actually held.
 */
async function openTreeEntry(absolutePath, relativePath, extraFlags = 0) {
  try {
    return await fsOpen(absolutePath, O_RDONLY | symlinkSafeOpenFlag() | nonBlockingOpenFlag() | extraFlags);
  } catch (error) {
    if (error?.code === "ELOOP" || error?.code === "EMLINK") {
      throw new Error(`dependency tree contains a symbolic link: ${relativePath}`);
    }
    throw error;
  }
}

/**
 * Re-open a directory BY NAME and require it to be the very object that was listed.
 *
 * Node exposes no `openat`, so a recursion cannot be carried on a held descriptor: `/dev/fd/N`
 * answers ENOTDIR for a directory on macOS and `/proc/self/fd` does not exist there, both measured.
 * The traversal therefore cannot be made atomic. What these probes establish is narrower and is
 * stated as such: a substitution that is STILL PRESENT when a probe runs is detected and refused.
 * They do not, and cannot, guarantee that every transient swap is caught — an adversary who
 * substitutes and restores entirely between two probes leaves nothing for a probe to see. MEASURED: renaming a package subdirectory away
 * immediately after its `fstat` and leaving a symlink to an identical directory outside the package
 * tree produced a PASS with the exact expected digests. Now the same swap fails twice over: the
 * re-open refuses the symlink at O_NOFOLLOW, and a swapped real directory has a different
 * (device, inode) than the one whose entries were read.
 */
export async function assertDirectoryUnchanged(absolutePath, relativePath, identity) {
  let handle;
  try {
    handle = await openTreeEntry(absolutePath, relativePath, O_DIRECTORY);
  } catch (error) {
    // A name that no longer opens as the same kind of object is a replacement, and saying so is more
    // useful evidence than the raw errno: O_NOFOLLOW + O_DIRECTORY answers ENOTDIR when a symlink has
    // been put in the directory's place, which is exactly the reported swap.
    throw new Error(
      `dependency tree directory ${relativePath || "."} was replaced while it was being read ` +
      `(${error?.code ?? String(error && error.message)})`,
    );
  }
  try {
    const current = await reflectApply(handleStat, handle, []);
    if (
      !reflectApply(statsIsDirectory, current, [])
      || current.dev !== identity.dev || current.ino !== identity.ino
    ) {
      throw new Error(
        `dependency tree directory ${relativePath || "."} was replaced while it was being read`,
      );
    }
  } finally {
    await handle.close();
  }
}

export async function dependencyTreeDigest(packageDirectory) {
  const records = [];

  const walk = async (directory, prefix = "", expected = null) => {
    const label = prefix === "" ? "." : prefix;
    const dirHandle = await openTreeEntry(directory, label, O_DIRECTORY);
    let identity;
    try {
      const held = await reflectApply(handleStat, dirHandle, []);
      if (!reflectApply(statsIsDirectory, held, [])) {
        throw new Error(`dependency tree entry ${label} is not a directory`);
      }
      // THE PARENT ALREADY DECIDED WHICH DIRECTORY THIS IS. The parent opened this child, saw a
      // directory, closed the descriptor and then handed the PATH down — and re-opening a path is a
      // second lookup, so without this comparison the child would take whatever it found as its own
      // baseline and validate the replacement against itself. MEASURED against the earlier revision:
      // a different real directory moved into place between those two opens digested cleanly, and
      // both of that revision's identity probes agreed, because each was asking about the object it
      // had just opened rather than the object its parent listed.
      if (expected !== null && (held.dev !== expected.dev || held.ino !== expected.ino)) {
        throw new Error(
          `dependency tree directory ${label} was replaced between its listing and its descent`,
        );
      }
      identity = { dev: held.dev, ino: held.ino };
    } finally {
      await dirHandle.close();
    }

    const entries = reflectApply(
      arraySort,
      await fsReaddir(directory, { withFileTypes: true }),
      [bytewiseNameOrder],
    );
    // The listing is only evidence about the directory it actually came from.
    await assertDirectoryUnchanged(directory, label, identity);

    for (let index = 0; index < entries.length; index++) {
      const entry = entries[index];
      if (
        reflectApply(stringIncludes, entry.name, ["\0"]) ||
        reflectApply(stringIncludes, entry.name, ["\n"]) ||
        reflectApply(stringIncludes, entry.name, ["\r"])
      ) {
        throw new Error(`dependency tree contains an unrepresentable path component: ${JSON.stringify(entry.name)}`);
      }
      const relativePath = prefix === "" ? entry.name : `${prefix}/${entry.name}`;
      const absolutePath = pathJoin(directory, entry.name);
      const handle = await openTreeEntry(absolutePath, relativePath);
      let bytes = null;
      // Which directory this entry WAS, carried into the descent so the child cannot re-baseline.
      let childDirectory = null;
      try {
        const held = await reflectApply(handleStat, handle, []);
        if (reflectApply(statsIsDirectory, held, [])) childDirectory = { dev: held.dev, ino: held.ino };
        else if (reflectApply(statsIsFile, held, [])) bytes = await reflectApply(handleReadFile, handle, []);
        else throw new Error(`dependency tree contains a non-regular entry: ${relativePath}`);
      } finally {
        await handle.close();
      }
      if (bytes === null) {
        await walk(absolutePath, relativePath, childDirectory);
        continue;
      }
      reflectApply(arrayPush, records, [`${relativePath}\0${sha256(bytes)}`]);
    }

    // And the children are only evidence about this directory if it is still this directory.
    await assertDirectoryUnchanged(directory, label, identity);
  };

  await walk(packageDirectory);
  return objectFreeze({
    files: records.length,
    sha256: sha256(reflectApply(arrayJoin, records, ["\n"])),
  });
}

/** Resolve `<base>/<scoped/name>` through the captured splitter — never a live `String.prototype`. */
function packageDirectoryFor(base, name) {
  const segments = reflectApply(stringSplit, name, ["/"]);
  let directory = base;
  for (let index = 0; index < segments.length; index++) directory = pathResolve(directory, segments[index]);
  return directory;
}

/** Verify every byte and path in each complete dependency tree that the signer artifact bundles. */
export async function attestHardenedDependencyTrees({ packageRoot = DEFAULT_PACKAGE_ROOT } = {}) {
  const nodeModules = packageDirectoryFor(packageRoot, "node_modules");
  const realNodeModules = await fsRealpath(nodeModules);
  const evidence = [];
  // INDEX ITERATION, NOT `for…of`. MEASURED: replacing `Array.prototype[Symbol.iterator]` for this
  // exact receiver with an empty iterator made this function return normally having measured NOTHING
  // — zero packages, no throw, and the caller read that as a pass. An attestation that can be handed
  // an empty work list and still succeed is not an attestation, so the loop cannot be driven by a
  // replaceable protocol and the count is checked against the pinned list afterwards.
  for (let index = 0; index < HARDENED_PACKAGE_TREES.length; index++) {
    const expected = HARDENED_PACKAGE_TREES[index];
    const packageDirectory = packageDirectoryFor(nodeModules, expected.packageName);
    const realPackageDirectory = await fsRealpath(packageDirectory);
    if (!reflectApply(stringStartsWith, realPackageDirectory, [`${realNodeModules}${pathSep}`])) {
      throw new Error(`${expected.packageName} resolved outside signer-core node_modules`);
    }
    const actual = await dependencyTreeDigest(packageDirectory);
    if (actual.files !== expected.files || actual.sha256 !== expected.sha256) {
      throw new Error(
        `${expected.packageName}: complete dependency tree drift; expected ${expected.files} files / ` +
        `${expected.sha256}, found ${actual.files} files / ${actual.sha256}`,
      );
    }
    reflectApply(arrayPush, evidence, [objectFreeze({
      packageName: expected.packageName, files: actual.files, sha256: actual.sha256,
    })]);
  }
  if (evidence.length !== HARDENED_PACKAGE_TREES.length) {
    throw new Error(
      `dependency tree attestation measured ${evidence.length} of ${HARDENED_PACKAGE_TREES.length} ` +
      "packages; a partial attestation is a refusal",
    );
  }
  return objectFreeze(evidence);
}

export function transformSource(source, patch) {
  let transformed = source;
  for (let index = 0; index < patch.replacements.length; index++) {
    const replacement = patch.replacements[index];
    const first = transformed.indexOf(replacement.before);
    const second = first === -1 ? -1 : transformed.indexOf(replacement.before, first + replacement.before.length);
    if (first === -1 || second !== -1) {
      throw new Error(
        `${patch.packageName}/${patch.relativePath}: replacement ${index + 1} matched ${first === -1 ? 0 : "more than 1"} times`,
      );
    }
    transformed = `${transformed.slice(0, first)}${replacement.after}${transformed.slice(first + replacement.before.length)}`;
  }
  return transformed;
}

/**
 * Open a path once, prove from the DESCRIPTOR that it is a regular unlinked file, and return both the
 * stat and the bytes. The previous shape `lstat`-ed the path and let the caller `readFile` it again —
 * the same check-then-use window the tree attestation had, on the very path this transformer is about
 * to overwrite. One descriptor answers both questions about one object.
 */
async function readRegularUnlinkedFile(path, label) {
  let handle;
  try {
    handle = await fsOpen(path, O_RDONLY | symlinkSafeOpenFlag() | nonBlockingOpenFlag());
  } catch (error) {
    if (error?.code === "ELOOP" || error?.code === "EMLINK") {
      throw new Error(`${label} is not a regular, unlinked file: ${path}`);
    }
    throw error;
  }
  try {
    const stat = await reflectApply(handleStat, handle, []);
    if (!reflectApply(statsIsFile, stat, [])) {
      throw new Error(`${label} is not a regular, unlinked file: ${path}`);
    }
    return { stat, source: await reflectApply(handleReadFile, handle, ["utf8"]) };
  } finally {
    await handle.close();
  }
}

async function atomicWrite(path, content, mode) {
  const temporary = `${path}.noa-hardening-${process.pid}`;
  let handle;
  try {
    handle = await fsOpen(temporary, "wx", mode & 0o777);
    await handle.writeFile(content, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    await fsRename(temporary, path);
  } catch (error) {
    await handle?.close().catch(() => undefined);
    await fsUnlink(temporary).catch(() => undefined);
    throw error;
  }
}

function assertPolicyCurrent(now) {
  if (!reflectApply(numberIsFinite, Number, [now])) {
    throw new Error("dependency hardening clock is not finite");
  }
  if (now >= reflectApply(dateParse, Date, [HARDENING_POLICY.expiresAt])) {
    throw new Error(
      `${HARDENING_POLICY.id} expired after ${HARDENING_POLICY.reviewBy}; review upstream replacements before continuing`,
    );
  }
}

export async function hardenDependencies({
  checkOnly = false,
  packageRoot = DEFAULT_PACKAGE_ROOT,
  // The clock the expiry gate reads is a dependency like any other: a live `Date.now` can be handed
  // back a time of the adversary's choosing, and this policy's whole purpose is to stop being valid.
  now = reflectApply(dateNow, Date, []),
} = {}) {
  assertPolicyCurrent(now);
  // The same captured resolver the attestation uses, so there is ONE resolution path under one
  // load-bearing control rather than a second one nothing exercises.
  const nodeModules = packageDirectoryFor(packageRoot, "node_modules");
  // npm runs a linked package's `postinstall` in contexts where that package has no dependency tree
  // of its own — MEASURED: `npm ci packages/e2e-demo` invoked this transformer against a
  // signer-core with no `node_modules`, and the ENOENT from `realpath` failed the whole install.
  // There is nothing to transform there, and saying so is honest. The asymmetry is deliberate:
  // `--check` is the gate, so a check that cannot SEE the tree is a refusal, never a pass.
  let realNodeModules;
  try {
    realNodeModules = await fsRealpath(nodeModules);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    if (checkOnly) {
      throw new Error(
        `${nodeModules} does not exist, so the hardened dependency state cannot be verified here`,
      );
    }
    return objectFreeze({
      checked: 0, changed: 0, trees: 0, skipped: true, policyId: HARDENING_POLICY.id,
    });
  }
  const prepared = [];
  const manifests = new Map();

  for (let patchIndex = 0; patchIndex < PATCHES.length; patchIndex++) {
    const patch = PATCHES[patchIndex];
    const packageDirectory = packageDirectoryFor(nodeModules, patch.packageName);
    const manifestPath = pathResolve(packageDirectory, "package.json");
    if (!manifests.has(manifestPath)) {
      const manifestFile = await readRegularUnlinkedFile(manifestPath, `${patch.packageName} manifest`);
      const realManifestPath = await fsRealpath(manifestPath);
      if (!reflectApply(stringStartsWith, realManifestPath, [`${realNodeModules}${pathSep}`])) {
        throw new Error(`${patch.packageName} resolved outside signer-core node_modules: ${realManifestPath}`);
      }
      const manifest = JSON.parse(manifestFile.source);
      if (manifest.name !== patch.packageName || manifest.version !== patch.version) {
        throw new Error(
          `${patch.packageName}: expected ${patch.version}, found ${String(manifest.name)}@${String(manifest.version)}`,
        );
      }
      manifests.set(manifestPath, manifest);
    }

    const targetPath = pathResolve(packageDirectory, patch.relativePath);
    const target = await readRegularUnlinkedFile(targetPath, `${patch.packageName}/${patch.relativePath}`);
    const stat = target.stat;
    const realTargetPath = await fsRealpath(targetPath);
    if (!reflectApply(stringStartsWith, realTargetPath, [`${realNodeModules}${pathSep}`])) {
      throw new Error(`${patch.packageName}/${patch.relativePath} resolved outside signer-core node_modules`);
    }
    const source = target.source;
    const actualHash = sha256(source);
    if (actualHash === patch.afterSha256) {
      reflectApply(arrayPush, prepared, [{ patch, targetPath, stat, status: "hardened", transformed: source }]);
      continue;
    }
    if (actualHash !== patch.beforeSha256) {
      throw new Error(
        `${patch.packageName}/${patch.relativePath}: unknown bytes ${actualHash}; expected ${patch.beforeSha256} or ${patch.afterSha256}`,
      );
    }
    if (checkOnly) {
      throw new Error(`${patch.packageName}/${patch.relativePath}: exact dependency hardening is not applied`);
    }
    const transformed = transformSource(source, patch);
    const transformedHash = sha256(transformed);
    if (transformedHash !== patch.afterSha256) {
      throw new Error(
        `${patch.packageName}/${patch.relativePath}: transformed hash ${transformedHash} != ${patch.afterSha256}`,
      );
    }
    reflectApply(arrayPush, prepared, [{ patch, targetPath, stat, status: "pending", transformed }]);
  }

  for (let preparedIndex = 0; preparedIndex < prepared.length; preparedIndex++) {
    const item = prepared[preparedIndex];
    if (item.status === "pending") {
      await atomicWrite(item.targetPath, item.transformed, item.stat.mode);
      const writtenHash = sha256(await fsReadFile(item.targetPath));
      if (writtenHash !== item.patch.afterSha256) {
        throw new Error(`${item.patch.packageName}/${item.patch.relativePath}: post-write verification failed`);
      }
    }
  }

  const trees = await attestHardenedDependencyTrees({ packageRoot });
  let changed = 0;
  for (let index = 0; index < prepared.length; index++) {
    if (prepared[index].status === "pending") changed++;
  }
  return objectFreeze({ checked: prepared.length, changed, trees: trees.length, policyId: HARDENING_POLICY.id });
}

function parseMode(argv) {
  if (argv.length !== 1 || !["--apply", "--check"].includes(argv[0])) {
    throw new Error("usage: node scripts/apply-dependency-hardening.mjs <--apply|--check>");
  }
  return argv[0] === "--check";
}

const invokedPath = process.argv[1] ? pathResolve(process.argv[1]) : "";
if (invokedPath === urlFileURLToPath(import.meta.url)) {
  try {
    const checkOnly = parseMode(process.argv.slice(2));
    const result = await hardenDependencies({ checkOnly });
    console.log(result.skipped === true
      ? `dependency hardening skipped: no dependency tree beside this package, nothing to apply, ${result.policyId}`
      : `dependency hardening ${checkOnly ? "verified" : "applied"}: ${result.checked}/${result.checked} exact patches, ` +
        `${result.trees}/${result.trees} complete package trees, ${result.changed} changed, ${result.policyId}`,
    );
  } catch (error) {
    console.error(`dependency hardening failed: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}
