import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { readdir } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { cp, mkdir, mkdtemp, open, readFile, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  assertDirectoryUnchanged,
  nonBlockingOpenFlag,
  dependencyTreeDigest,
  symlinkSafeOpenFlag,
  HARDENED_ARTIFACT_PATHS,
  HARDENED_PACKAGE_NAMES,
  HARDENED_PACKAGE_TREES,
  HARDENING_POLICY,
  attestHardenedDependencyTrees,
  hardenDependencies,
  transformSource,
} from "../scripts/apply-dependency-hardening.mjs";

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

test("signReceipt enters the private-seed cleanup scope before receipt hashing", async () => {
  const source = await readFile(join(PACKAGE_ROOT, "src", "sign.ts"), "utf8");
  const extraction = "const seed = pkcs8Ed25519ToRawSeed(signer.privateKey);";
  const cleanupScope = "return withZeroedCryptoBytes(seed, (privateSeed) => {";
  assert.equal(source.split(extraction).length - 1, 1, "private seed extraction is no longer a single reviewable site");
  assert.equal(source.split(cleanupScope).length - 1, 1, "signReceipt no longer binds the extracted seed to its cleanup scope");
  const between = source.slice(source.indexOf(extraction) + extraction.length, source.indexOf(cleanupScope));
  assert.doesNotMatch(
    between,
    /receiptHashInput|signingMessageBytes|signEd25519/,
    "private-key extraction is followed by a throwing operation before the cleanup scope starts",
  );
});

test("post-load readFile poisoning cannot hide malicious bytes from the attestation", async () => {
  // ── THE REPRODUCTION THIS PINS ────────────────────────────────────────────────────────────────
  // Import this module first, then replace `FileHandle.prototype.readFile` so the one held inode
  // returns the original clean bytes. MEASURED against the earlier revision: the attestation returned
  // PASS with the exact expected counts and digests while the file on disk said
  // "MALICIOUS BUT HIDDEN FROM ATTESTATION". `stat` and `readFile` are shared prototype dispatch, so
  // they are bound at module load and invoked through a captured Reflect.apply instead.
  const root = await mkdtemp(join(tmpdir(), "noa-readfile-poison-"));
  const probe = await open(join(PACKAGE_ROOT, "package.json"), "r");
  const fileHandlePrototype = Object.getPrototypeOf(probe);
  const realReadFile = fileHandlePrototype.readFile;
  try {
    await probe.close();
    await mkdir(join(root, "pkg"), { recursive: true });
    const victim = join(root, "pkg", "sha2.js");
    const CLEAN = "CLEAN ORIGINAL BYTES\n";
    const MALICIOUS = "MALICIOUS BUT HIDDEN FROM ATTESTATION\n";
    await writeFile(victim, CLEAN);
    const clean = await dependencyTreeDigest(join(root, "pkg"));

    await writeFile(victim, MALICIOUS);
    const cleanBytes = Buffer.from(CLEAN);
    fileHandlePrototype.readFile = async function poisoned(...args) {
      const held = await this.stat();
      if (held.size === Buffer.byteLength(MALICIOUS)) return cleanBytes;
      return realReadFile.apply(this, args);
    };

    // ANTI-VACUITY: the poison must genuinely work against live dispatch, or this proves nothing.
    const live = await open(victim, "r");
    const livesaw = await live.readFile();
    await live.close();
    assert.equal(livesaw.toString(), CLEAN,
      "the poison no longer fools live dispatch — this regression has gone vacuous");

    const attested = await dependencyTreeDigest(join(root, "pkg"));
    assert.notEqual(attested.sha256, clean.sha256,
      "the attestation reported the clean digest for malicious bytes: post-load readFile poisoning is hiding content from the evidence");
  } finally {
    fileHandlePrototype.readFile = realReadFile;
    await rm(root, { recursive: true, force: true });
  }
});

test("a directory substitution still present at the identity probe is refused", async () => {
  // ── THE REPRODUCTION THIS PINS ────────────────────────────────────────────────────────────────
  // Rename a package subdirectory away immediately after its `fstat` and leave a symlink to an
  // identical directory OUTSIDE the package tree. MEASURED against the earlier revision: PASS, with
  // the exact expected digests, for a traversal that had left the package. Node exposes no `openat`
  // (`/dev/fd/N` answers ENOTDIR for a directory on macOS and `/proc/self/fd` does not exist there,
  // both measured), so the traversal cannot be made atomic. These probes establish only that a
  // substitution STILL PRESENT at a probe is refused; a swap made and undone entirely between two
  // probes leaves nothing to observe, and nothing here claims otherwise.
  //
  // The check is exercised directly rather than through a production callback: a test seam on the
  // walk would have widened the shipped API for the benefit of one test.
  const root = await mkdtemp(join(tmpdir(), "noa-dir-identity-"));
  try {
    await mkdir(join(root, "real"), { recursive: true });
    const held = await open(join(root, "real"), "r");
    const stat = await held.stat();
    await held.close();
    const identity = { dev: stat.dev, ino: stat.ino };

    // ANTI-VACUITY: the directory that WAS listed is accepted.
    await assertDirectoryUnchanged(join(root, "real"), "real", identity);

    // A different real directory under the same name is refused on identity.
    await rename(join(root, "real"), join(root, "moved"));
    await mkdir(join(root, "real"));
    await assert.rejects(
      assertDirectoryUnchanged(join(root, "real"), "real", identity),
      /was replaced while it was being read/,
      "a substituted directory kept the identity of the one whose entries were read",
    );

    // And a symlink in its place is refused at open time, before any identity comparison.
    await rm(join(root, "real"), { recursive: true, force: true });
    await symlink(join(root, "moved"), join(root, "real"));
    await assert.rejects(
      assertDirectoryUnchanged(join(root, "real"), "real", identity),
      /was replaced while it was being read/,
      "a symlink was traversed in place of the listed directory",
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("the tree walk probes directory identity on both sides of every listing", async () => {
  // The unit above proves the check refuses. This proves the walk USES it — on both sides of the
  // listing, because a swap before the children are read and a swap after them are different windows.
  const source = await readFile(join(PACKAGE_ROOT, "scripts", "apply-dependency-hardening.mjs"), "utf8");
  const walkStart = source.indexOf("const walk = async (directory, prefix");
  const walkEnd = source.indexOf("await walk(packageDirectory);");
  assert.ok(walkStart !== -1 && walkEnd > walkStart, "the tree walk moved; this assertion is now vacuous");
  const walk = source.slice(walkStart, walkEnd);
  const checks = walk.split("await assertDirectoryUnchanged(directory, label, identity);").length - 1;
  assert.equal(checks, 2,
    `the walk performs ${checks} directory-identity re-binding(s); it needs one after the listing and one after the children`);
});

test("a poisoned Array iterator cannot empty the attestation's work list", async () => {
  // ── THE REPRODUCTION THIS PINS ────────────────────────────────────────────────────────────────
  // Replace `Array.prototype[Symbol.iterator]` for the exported pinned list alone with an empty
  // iterator. MEASURED against the earlier revision: the attestation returned NORMALLY having
  // measured nothing — evidence length 0, no throw — and a caller read that as a pass. An
  // attestation that can be handed an empty work list and still succeed is not an attestation.
  const realIterator = Array.prototype[Symbol.iterator];
  try {
    Array.prototype[Symbol.iterator] = function poisoned() {
      if (this === HARDENED_PACKAGE_TREES) return { next: () => ({ done: true, value: undefined }) };
      return realIterator.call(this);
    };
    // ANTI-VACUITY: the poison genuinely empties an ordinary iteration of that exact array.
    const drained = [];
    for (const entry of HARDENED_PACKAGE_TREES) drained.push(entry);
    assert.equal(drained.length, 0, "the poison no longer empties a for-of over the pinned list");

    const evidence = await attestHardenedDependencyTrees();
    assert.equal(evidence.length, HARDENED_PACKAGE_TREES.length,
      "the attestation measured fewer packages than it is pinned to, and still returned");
  } finally {
    Array.prototype[Symbol.iterator] = realIterator;
  }
});

test("a poisoned Date.now cannot move the hardening policy's expiry clock", async () => {
  // The expiry gate exists so this transformer stops being trusted on a date. A live `Date.now` hands
  // that date to whoever replaced it, so the clock is captured at module load. NaN is the observable
  // probe: read live it trips "clock is not finite", read from the capture it never reaches the gate.
  const emptyRoot = await mkdtemp(join(tmpdir(), "noa-clock-poison-"));
  const realNow = Date.now;
  try {
    // ANTI-VACUITY: the gate genuinely refuses a non-finite clock when one is actually supplied.
    await assert.rejects(
      hardenDependencies({ checkOnly: true, packageRoot: emptyRoot, now: Number.NaN }),
      /clock is not finite/,
      "the expiry gate stopped refusing a non-finite clock — this regression has gone vacuous",
    );

    Date.now = () => Number.NaN;
    await assert.rejects(
      hardenDependencies({ checkOnly: true, packageRoot: emptyRoot }),
      /cannot be verified here/,
      "the default clock came from the live Date.now, so a replaced clock reaches the expiry gate",
    );
  } finally {
    Date.now = realNow;
    await rm(emptyRoot, { recursive: true, force: true });
  }
});

/**
 * ONE reusable fixture for every "the attestation's own machinery was replaced" regression.
 *
 * It copies the three real hardened trees into a private root, tampers with a single file WITHOUT
 * changing any file count — so only the BYTES can betray it — and independently recomputes what the
 * clean records and clean aggregate inputs would have been. That last part is what lets a poison
 * construct a genuine false PASS rather than merely being counted: a substitution that hands back
 * the real clean values makes a live-dispatch build return the pinned digests for a tampered tree,
 * which is exactly the reported reproduction.
 *
 * The record shape and ordering mirror the transformer's own walk: entries sorted by a bytewise
 * comparison of their names, recursed depth-first, each record `<relative path>\0<sha256 of bytes>`.
 */
async function hardenedTreeFixture() {
  const root = await mkdtemp(join(tmpdir(), "noa-attestation-fixture-"));
  const segmentsOf = (name) => name.split("/");

  for (const tree of HARDENED_PACKAGE_TREES) {
    await cp(
      join(PACKAGE_ROOT, "node_modules", ...segmentsOf(tree.packageName)),
      join(root, "node_modules", ...segmentsOf(tree.packageName)),
      { recursive: true },
    );
  }

  const digestOf = (bytes) => createHash("sha256").update(bytes).digest("hex");
  const recordsFor = async (directory, prefix = "") => {
    const entries = (await readdir(directory, { withFileTypes: true }))
      .sort((left, right) => Buffer.from(left.name).compare(Buffer.from(right.name)));
    const out = [];
    for (const entry of entries) {
      const relative = prefix === "" ? entry.name : `${prefix}/${entry.name}`;
      const absolute = join(directory, entry.name);
      if (entry.isDirectory()) out.push(...await recordsFor(absolute, relative));
      else out.push(`${relative}\0${digestOf(await readFile(absolute))}`);
    }
    return out;
  };

  // Recorded BEFORE the tamper, so they are the values a clean run would have produced.
  const cleanRecordsByTree = [];
  for (const tree of HARDENED_PACKAGE_TREES) {
    cleanRecordsByTree.push(await recordsFor(join(root, "node_modules", ...segmentsOf(tree.packageName))));
  }

  // A pristine copy of every tree, OUTSIDE node_modules: what a redirect would hand back instead.
  for (const tree of HARDENED_PACKAGE_TREES) {
    await cp(
      join(root, "node_modules", ...segmentsOf(tree.packageName)),
      join(root, "clean", ...segmentsOf(tree.packageName)),
      { recursive: true },
    );
  }

  // One DISTINCT pristine copy per package, each a sibling of node_modules, so a redirect can name
  // exactly one of them. They are made before the tamper, so each is byte-identical to its pin.
  const externalCopies = {};
  for (const tree of HARDENED_PACKAGE_TREES) {
    const name = `clean-${tree.packageName.split("/").at(-1)}`;
    await cp(join(root, "node_modules", ...segmentsOf(tree.packageName)), join(root, name), { recursive: true });
    externalCopies[tree.packageName] = name;
  }

  // One file changes; no file count does.
  const tampered = join(root, "node_modules", "@noble", "ciphers", "package.json");
  await writeFile(tampered, `${await readFile(tampered, "utf8")}\n`);

  const nodeModules = join(root, "node_modules");
  const cleanCopies = join(root, "clean");
  return {
    root,
    externalCopies,
    tampered,
    redirect: (candidate) => (typeof candidate === "string" && candidate.startsWith(nodeModules)
      ? cleanCopies + candidate.slice(nodeModules.length)
      : candidate),
    cleanRecordsByTree,
    cleanRecords: cleanRecordsByTree.flat(),
    cleanAggregateInputs: cleanRecordsByTree.map((records) => records.join("\n")),
    dispose: () => rm(root, { recursive: true, force: true }),
  };
}

test("the shared attestation fixture really is tampered and really is same-count", async () => {
  // If the fixture stopped being tampered, or its recomputed records stopped matching the pinned
  // counts, every regression built on it would pass for the wrong reason.
  const fixture = await hardenedTreeFixture();
  try {
    assert.equal(fixture.cleanRecords.length, 165, "the recomputed clean record set no longer covers all three trees");
    for (const [index, tree] of HARDENED_PACKAGE_TREES.entries()) {
      assert.equal(fixture.cleanRecordsByTree[index].length, tree.files,
        `${tree.packageName}: recomputed ${fixture.cleanRecordsByTree[index].length} records, pinned at ${tree.files}`);
    }
    await assert.rejects(
      attestHardenedDependencyTrees({ packageRoot: fixture.root }),
      /complete dependency tree drift/,
      "the fixture is no longer tampered, so nothing built on it is measuring a bypass",
    );
  } finally {
    await fixture.dispose();
  }
});

/**
 * Run one builtin-redirect reproduction end to end.
 *
 * A named import from a Node builtin is a LIVE BINDING: replacing the property on the CommonJS
 * object and calling `syncBuiltinESMExports()` re-points every importer's binding, including this
 * transformer's. Each redirect below is independently sufficient to produce a false PASS, so each is
 * measured on its own rather than as a group.
 */
async function builtinRedirectIsRefused({ moduleName, properties, liveProbe, redirectsArgument }) {
  const fixture = await hardenedTreeFixture();
  const require = createRequire(import.meta.url);
  const target = require(moduleName);
  const originals = new Map(properties.map((name) => [name, target[name]]));
  let redirects = 0;
  try {
    for (const name of properties) {
      const real = originals.get(name);
      // `fs` helpers redirect their FIRST ARGUMENT and must be called exactly once — calling first
      // and redirecting afterwards opened a FileHandle per attempt (up to ~194) and left the
      // discarded promises unhandled. `path` helpers are synchronous and redirect their result.
      target[name] = redirectsArgument
        ? function redirectedArgument(...args) {
          const moved = fixture.redirect(args[0]);
          if (moved !== args[0]) redirects += 1;
          return real.apply(this, [moved, ...args.slice(1)]);
        }
        : function redirectedResult(...args) {
          const result = real.apply(this, args);
          const moved = fixture.redirect(result);
          if (moved !== result) redirects += 1;
          return moved;
        };
    }
    syncBuiltinESMExports();

    // ANTI-VACUITY: the replacement really does reach an importer's live binding.
    await liveProbe(fixture);
    assert.ok(redirects > 0,
      `${moduleName}: the replacement never redirected through a live binding — this regression has gone vacuous`);
    redirects = 0;

    await assert.rejects(
      attestHardenedDependencyTrees({ packageRoot: fixture.root }),
      /complete dependency tree drift/,
      `${moduleName}: reads were redirected to pristine copies and the tampered tree attested as clean`,
    );
    assert.equal(redirects, 0,
      `${moduleName}: the attestation made ${redirects} call(s) through the re-pointed live binding`);

    // Proven present after the attempt, not assumed.
    assert.ok((await readFile(fixture.tampered, "utf8")).endsWith("\n\n"),
      "the tampered file stopped being tampered, so nothing here measured a bypass");
  } finally {
    for (const name of properties) target[name] = originals.get(name);
    syncBuiltinESMExports();
    await fixture.dispose();
  }
}

test("a re-pointed fs/promises open and readdir cannot redirect the attestation's reads", async () => {
  // MEASURED against live bindings: 194 opens and 8 readdirs redirected, evidence=3, malicious intact.
  await builtinRedirectIsRefused({
    moduleName: "fs/promises",
    properties: ["open", "readdir"],
    redirectsArgument: true,
    liveProbe: async (fixture) => {
      const live = await import("node:fs/promises");
      const handle = await live.open(join(fixture.root, "node_modules", "@noble", "ciphers", "package.json"), "r");
      await handle.close();
    },
  });
});

test("a re-pointed path.resolve cannot redirect the attestation's package roots", async () => {
  // MEASURED against a live binding: 3 redirects — one per package root — evidence=3, malicious intact.
  await builtinRedirectIsRefused({
    moduleName: "path",
    properties: ["resolve"],
    redirectsArgument: false,
    liveProbe: async (fixture) => {
      const live = await import("node:path");
      live.resolve(fixture.root, "node_modules", "@noble", "ciphers");
    },
  });
});

test("a re-pointed path.join cannot redirect the attestation's file reads", async () => {
  // MEASURED against a live binding: a single redirect of the changed file's path was enough —
  // evidence=3, malicious intact. One call site is sufficient, so `join` is proven on its own.
  await builtinRedirectIsRefused({
    moduleName: "path",
    properties: ["join"],
    redirectsArgument: false,
    liveProbe: async (fixture) => {
      const live = await import("node:path");
      live.join(fixture.root, "node_modules", "@noble", "ciphers", "package.json");
    },
  });
});

test("a poisoned Array.push cannot substitute the per-file records", async () => {
  // ── THE REPRODUCTION THIS PINS ────────────────────────────────────────────────────────────────
  // Replace `Array.prototype.push` and hand back the 165 clean records in order. Under live dispatch
  // that makes a same-count tampered tree produce the pinned digests: the bytes on disk are never
  // consulted again after they are hashed, so whatever reaches the record list IS the measurement.
  const fixture = await hardenedTreeFixture();
  const realPush = Array.prototype.push;
  try {
    let calls = 0;
    Array.prototype.push = function poisoned(...args) {
      if (args.length === 1 && typeof args[0] === "string" && args[0].includes("\0")) {
        const substitute = fixture.cleanRecords[calls];
        calls += 1;
        if (substitute !== undefined) return realPush.call(this, substitute);
      }
      return realPush.apply(this, args);
    };

    // ANTI-VACUITY: the poison genuinely substitutes a record through a live push.
    const observed = [];
    observed.push(`package.json\0${"f".repeat(64)}`);
    assert.equal(observed[0], fixture.cleanRecords[0],
      "the poison no longer substitutes records on a live push — this regression has gone vacuous");
    calls = 0;

    await assert.rejects(
      attestHardenedDependencyTrees({ packageRoot: fixture.root }),
      /complete dependency tree drift/,
      "the record list was substituted wholesale and the tampered tree attested as pristine",
    );
    assert.equal(calls, 0,
      `the attestation routed ${calls} record append(s) through live Array.prototype.push, which is the slot the reproduction replaced`);
  } finally {
    Array.prototype.push = realPush;
    await fixture.dispose();
  }
});

test("a poisoned Array.join cannot substitute the aggregate inputs", async () => {
  // ── THE REPRODUCTION THIS PINS ────────────────────────────────────────────────────────────────
  // Replace `Array.prototype.join` and hand back the three clean aggregate inputs. The aggregate is
  // the single string each tree's pinned digest is taken over, so substituting it is substituting the
  // whole tree's measurement — one call per tree, no per-file tampering required.
  const fixture = await hardenedTreeFixture();
  const realJoin = Array.prototype.join;
  try {
    let calls = 0;
    Array.prototype.join = function poisoned(...args) {
      if (args.length === 1 && args[0] === "\n" && this.length > 0) {
        const substitute = fixture.cleanAggregateInputs[calls];
        calls += 1;
        if (substitute !== undefined) return substitute;
      }
      return realJoin.apply(this, args);
    };

    // ANTI-VACUITY: the poison genuinely substitutes an aggregate input through a live join.
    const substituted = ["anything", "at all"].join("\n");
    assert.equal(substituted, fixture.cleanAggregateInputs[0],
      "the poison no longer substitutes aggregate inputs on a live join — this regression has gone vacuous");
    calls = 0;

    await assert.rejects(
      attestHardenedDependencyTrees({ packageRoot: fixture.root }),
      /complete dependency tree drift/,
      "the aggregate input was substituted and the tampered tree attested as pristine",
    );
    assert.equal(calls, 0,
      `the attestation routed ${calls} aggregate join(s) through live Array.prototype.join, which is the slot the reproduction replaced`);
  } finally {
    Array.prototype.join = realJoin;
    await fixture.dispose();
  }
});

test("a poisoned Reflect.apply cannot substitute results the captured intrinsics return", async () => {
  // ── THE REPRODUCTION THIS PINS ────────────────────────────────────────────────────────────────
  // Capturing each intrinsic is worth nothing if the DISPATCHER that invokes them is live. Replacing
  // `Reflect.apply` intercepts every captured call and can substitute its RESULT without touching the
  // captured function at all. MEASURED against a live-dispatcher mutant: 2236 dispatches, 168 of them
  // digests, forged at the derived aggregate positions — evidence=3 for a tampered tree.
  const fixture = await hardenedTreeFixture();
  const realApply = Reflect.apply;
  const realDigest = Object.getPrototypeOf(createHash("sha256")).digest;
  try {
    const aggregateAt = new Map();
    let position = 0;
    for (const tree of HARDENED_PACKAGE_TREES) {
      position += tree.files + 1;
      aggregateAt.set(position, tree.sha256);
    }

    let dispatches = 0;
    let digests = 0;
    Reflect.apply = function poisoned(target, thisArg, args) {
      dispatches += 1;
      if (target === realDigest) {
        digests += 1;
        const forged = aggregateAt.get(digests);
        if (forged !== undefined) return forged;
      }
      return realApply(target, thisArg, args);
    };

    // ANTI-VACUITY: the replacement really is on the dispatcher every captured call goes through.
    const probe = createHash("sha256");
    realApply(Object.getPrototypeOf(probe).update, probe, ["anything"]);
    assert.ok(dispatches === 0, "the anti-vacuity probe must not itself dispatch through the poison");
    Reflect.apply(realDigest, probe, ["hex"]);
    assert.ok(dispatches > 0 && digests > 0,
      "the poison never saw a dispatch — this regression has gone vacuous");
    dispatches = 0;
    digests = 0;

    await assert.rejects(
      attestHardenedDependencyTrees({ packageRoot: fixture.root }),
      /complete dependency tree drift/,
      "the dispatcher substituted the captured intrinsics' results and the tampered tree attested as clean",
    );
    assert.equal(dispatches, 0,
      `the attestation made ${dispatches} dispatch(es) through the live Reflect.apply the reproduction replaced`);
  } finally {
    Reflect.apply = realApply;
    await fixture.dispose();
  }
});

test("a poisoned Hash.digest cannot substitute the aggregate tree digests", async () => {
  // ── THE REPRODUCTION THIS PINS ────────────────────────────────────────────────────────────────
  // Copy all three real hardened trees, change one file WITHOUT changing the file count, then
  // post-import replace `Hash.prototype.digest` so that only the AGGREGATE call for each tree returns
  // that tree's pinned digest. MEASURED against a live-hash mutant: evidence=3 after 168 digest calls,
  // for a tree that had been modified. A digest function is the last thing a measurement passes
  // through, so replacing it replaces the measurement outright — no file has to be read differently.
  //
  // The aggregate positions are DERIVED from the pinned file counts, not written down: each tree
  // produces one digest per file and then one aggregate, so with 33/72/60 files the aggregates land
  // at calls 34, 107 and 168. Hard-coding them would rot the moment a dependency gains a file.
  const fixture = await hardenedTreeFixture();
  const hashPrototype = Object.getPrototypeOf(createHash("sha256"));
  const realDigest = hashPrototype.digest;
  try {
    const aggregateAt = new Map();
    let position = 0;
    for (const tree of HARDENED_PACKAGE_TREES) {
      position += tree.files + 1;
      aggregateAt.set(position, tree.sha256);
    }

    let calls = 0;
    hashPrototype.digest = function poisoned(...args) {
      calls += 1;
      const forged = aggregateAt.get(calls);
      if (forged !== undefined) return forged;
      return realDigest.apply(this, args);
    };

    // ANTI-VACUITY: the poison genuinely substitutes at a derived aggregate position.
    calls = HARDENED_PACKAGE_TREES[0].files;
    const substituted = createHash("sha256").update("anything at all").digest("hex");
    assert.equal(substituted, HARDENED_PACKAGE_TREES[0].sha256,
      "the poison no longer substitutes at the derived aggregate position — this regression has gone vacuous");
    // Reset, so the attestation faces a full-strength poison rather than a partly spent one.
    calls = 0;

    await assert.rejects(
      attestHardenedDependencyTrees({ packageRoot: fixture.root }),
      /complete dependency tree drift/,
      "a tampered tree was attested as pristine because its aggregate digest was substituted",
    );
    assert.equal(calls, 0,
      `the attestation routed ${calls} hash call(s) through live Hash.prototype dispatch, which is the slot the reproduction replaced`);
  } finally {
    hashPrototype.digest = realDigest;
    await fixture.dispose();
  }
});

test("a poisoned Object.freeze cannot substitute the attestation's own measurement", async () => {
  // ── THE REPRODUCTION THIS PINS ────────────────────────────────────────────────────────────────
  // Patch the live `Object.freeze` so that only `{files, sha256}` digest objects come back as the
  // pinned expectations, in sequence. MEASURED against the earlier revision: the attestation returned
  // normally with the exact 33/72/60 evidence while every real tree contained nothing but
  // MALICIOUS.txt. The last function a measurement passes through can replace the measurement.
  const root = await mkdtemp(join(tmpdir(), "noa-freeze-poison-"));
  const realFreeze = Object.freeze;
  try {
    for (const name of ["@noble/ciphers", "@noble/curves", "@noble/hashes"]) {
      const victim = join(root, "node_modules", ...name.split("/"));
      await mkdir(victim, { recursive: true });
      await writeFile(join(victim, "MALICIOUS.txt"), "owned\n");
    }
    let served = 0;
    Object.freeze = function poisoned(value) {
      if (
        value !== null && typeof value === "object" &&
        typeof value.files === "number" && typeof value.sha256 === "string" &&
        served < HARDENED_PACKAGE_TREES.length
      ) {
        const expectation = HARDENED_PACKAGE_TREES[served++];
        return realFreeze({ files: expectation.files, sha256: expectation.sha256 });
      }
      return realFreeze(value);
    };

    // ANTI-VACUITY: the poison genuinely rewrites a digest-shaped object through a live call.
    const forged = Object.freeze({ files: 1, sha256: "not-the-real-digest" });
    assert.equal(forged.files, HARDENED_PACKAGE_TREES[0].files,
      "the poison no longer substitutes digest-shaped objects — this regression has gone vacuous");
    // The probe just consumed a substitution; reset so the attestation faces a full-strength poison
    // rather than one that runs out partway and refuses for the wrong reason.
    served = 0;

    await assert.rejects(
      attestHardenedDependencyTrees({ packageRoot: root }),
      /complete dependency tree drift/,
      "the attestation's own measurement was replaced on the way out and it still reported success",
    );
  } finally {
    Object.freeze = realFreeze;
    await rm(root, { recursive: true, force: true });
  }
});

test("poisoned string operations cannot redirect resolution out of node_modules", async () => {
  // ── THE REPRODUCTION THIS PINS ────────────────────────────────────────────────────────────────
  // Patch `String.prototype.split` so each package name resolves to a pristine copy OUTSIDE
  // node_modules, and `String.prototype.startsWith` to true so the containment check cannot object.
  // MEASURED against live string operations: every exact expected digest was returned from the clean
  // copies while the real trees under node_modules were tampered.
  //
  // The redirect targets are proven to be a WORKING forgery before the control is exercised: each
  // external copy is hashed on its own and must equal its pin. Without that, a refusal could mean
  // "the redirect pointed at nothing" rather than "the redirect was not followed", which is exactly
  // how an earlier version of this test passed for the wrong reason.
  const fixture = await hardenedTreeFixture();
  const realSplit = String.prototype.split;
  const realStartsWith = String.prototype.startsWith;
  try {
    // 1. Each redirect target independently hashes to its pin, so following one WOULD pass.
    for (const tree of HARDENED_PACKAGE_TREES) {
      const external = join(fixture.root, fixture.externalCopies[tree.packageName]);
      const digest = await dependencyTreeDigest(external);
      assert.equal(digest.files, tree.files, `${tree.packageName}: the redirect target is not the pinned shape`);
      assert.equal(digest.sha256, tree.sha256,
        `${tree.packageName}: the redirect target does not hash to its pin, so this test could pass merely because the redirect went nowhere`);
    }
    // …and the tree actually under node_modules does NOT, so only a followed redirect can pass.
    const tampered = await dependencyTreeDigest(join(fixture.root, "node_modules", "@noble", "ciphers"));
    assert.notEqual(tampered.sha256, HARDENED_PACKAGE_TREES[0].sha256,
      "the fixture's node_modules tree is not tampered, so nothing here distinguishes a redirect");

    // 2. Poison the two string operations resolution depends on.
    let redirects = 0;
    String.prototype.split = function poisoned(...args) {
      const external = fixture.externalCopies[this];
      if (external !== undefined && args[0] === "/") {
        redirects += 1;
        return ["..", external];
      }
      return realSplit.apply(this, args);
    };
    String.prototype.startsWith = function alwaysContained() { return true; };

    // ANTI-VACUITY: through LIVE string operations the redirect resolves to the clean copy, which is
    // the whole false PASS — the resolver would read a tree that hashes to the pin.
    const liveSegments = "@noble/ciphers".split("/");
    assert.deepEqual(liveSegments, ["..", fixture.externalCopies["@noble/ciphers"]],
      "the poison no longer redirects a live split — this regression has gone vacuous");
    assert.equal("/anything".startsWith("/nowhere"), true,
      "the poison no longer silences a live containment check — this regression has gone vacuous");
    const wouldHavePassed = await dependencyTreeDigest(
      join(fixture.root, "node_modules", ...liveSegments),
    );
    assert.equal(wouldHavePassed.sha256, HARDENED_PACKAGE_TREES[0].sha256,
      "following the redirect does not reach a pinned tree, so a false PASS was never on the table");
    redirects = 0;

    // 3. THE CONTROL: the attestation resolves through captured intrinsics, so it reads the tampered
    //    tree it was pointed at and refuses.
    await assert.rejects(
      attestHardenedDependencyTrees({ packageRoot: fixture.root }),
      /complete dependency tree drift/,
      "resolution was redirected out of node_modules and the attestation still passed",
    );
    assert.equal(redirects, 0,
      `the attestation resolved ${redirects} package name(s) through the live String.prototype.split the reproduction replaced`);
  } finally {
    String.prototype.split = realSplit;
    String.prototype.startsWith = realStartsWith;
    // Proven present after the attempt, not merely assumed.
    const stillThere = await readFile(join(fixture.root, "node_modules", "@noble", "hashes", "MALICIOUS.txt"), "utf8")
      .catch(() => null);
    assert.equal(stillThere, null,
      "this fixture tampers by MODIFYING a real tree; a stray MALICIOUS.txt means the fixture changed shape");
    await fixture.dispose();
  }
});

test("a directory swapped between its listing and its descent is refused", async () => {
  // ── THE REPRODUCTION THIS PINS ────────────────────────────────────────────────────────────────
  // The parent opens a child, sees a directory, closes the descriptor and hands the PATH down. The
  // descent re-opens that path — a second lookup — so before this control the child took whatever it
  // found as its OWN baseline and then validated the replacement against itself. Both identity
  // probes agreed, because each was asking about the object it had just opened rather than the
  // object its parent listed.
  //
  // The race is made DETERMINISTIC rather than raced for: `fs.promises.open` is replaced before the
  // module under test is imported, so the swap happens exactly between the two opens, every run. The
  // replacement is a real directory that STAYS in place, which is the case these probes can catch;
  // the documented limit is unchanged — a swap made and undone between two probes leaves nothing to
  // observe, and nothing here claims otherwise.
  const root = await mkdtemp(join(tmpdir(), "noa-descent-swap-"));
  const probe = join(root, "probe.mjs");
  await mkdir(join(root, "tree", "child"), { recursive: true });
  await writeFile(join(root, "tree", "child", "a.txt"), "original\n");
  await writeFile(join(root, "tree", "top.txt"), "top\n");
  // The replacement is a different real directory with different bytes, so a pass would be a digest
  // of something the walk never listed.
  await mkdir(join(root, "replacement"), { recursive: true });
  await writeFile(join(root, "replacement", "a.txt"), "swapped\n");
  await writeFile(probe, [
    'import { createRequire } from "node:module";',
    'import nodeModule from "node:module";',
    'const require = createRequire(import.meta.url);',
    'const fs = require("fs");',
    'const [root, moduleUrl, swap] = process.argv.slice(2);',
    'const target = require("path").join(root, "tree", "child");',
    '// Patch BEFORE the import: the module captures its builtins at load, so this is the open it captures.',
    'const realOpen = fs.promises.open;',
    'let swapsLeft = swap === "yes" ? 1 : 0;',
    'fs.promises.open = async function patched(...args) {',
    '  const handle = await realOpen.apply(this, args);',
    '  if (swapsLeft > 0 && args[0] === target) {',
    '    swapsLeft -= 1;',
    '    fs.renameSync(target, require("path").join(root, "moved"));',
    '    fs.renameSync(require("path").join(root, "replacement"), target);',
    '  }',
    '  return handle;',
    '};',
    'nodeModule.syncBuiltinESMExports();',
    'const { dependencyTreeDigest } = await import(moduleUrl);',
    'try {',
    '  const digest = await dependencyTreeDigest(require("path").join(root, "tree"));',
    '  console.log(JSON.stringify({ outcome: "PASSED", digest }));',
    '} catch (error) {',
    '  console.log(JSON.stringify({ outcome: "REFUSED", message: String(error && error.message) }));',
    '}',
  ].join("\n"));

  const moduleUrl = pathToFileURL(fileURLToPath(new URL("../scripts/apply-dependency-hardening.mjs", import.meta.url))).href;
  const run = (swap) => JSON.parse(execFileSync(process.execPath, [probe, root, moduleUrl, swap],
    { encoding: "utf8", timeout: 120_000 }).trim().split("\n").pop());

  try {
    // ANTI-VACUITY: the same fixture, same patched `open`, no swap — the walk completes. So a refusal
    // below is caused by the substitution and not by the harness.
    const undisturbed = run("no");
    assert.equal(undisturbed.outcome, "PASSED", `the unswapped walk did not complete: ${undisturbed.message}`);
    assert.equal(undisturbed.digest.files, 2, "the fixture is not the two-file tree this case assumes");

    const swapped = run("yes");
    assert.equal(swapped.outcome, "REFUSED",
      "a different real directory was moved in between the listing and the descent, and the walk digested it anyway");
    // The NEW check is what caught it. The older probes compare a directory against itself here, so a
    // "replaced while it was being read" message would mean this case is proving something else.
    assert.match(swapped.message, /was replaced between its listing and its descent/,
      `refused for the wrong reason: ${swapped.message}`);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a FIFO in a dependency tree is rejected, not waited on", async () => {
  // ── THE REPRODUCTION THIS PINS ────────────────────────────────────────────────────────────────
  // A blocking `O_RDONLY` on a FIFO waits for a writer that may never come. MEASURED: a tree
  // containing one made the attestation print its first line and then hang until it was killed at
  // six seconds — a denial of service on the release gate from a file type alone. The open is now
  // non-blocking and the FIFO is rejected by `fstat` as a non-regular entry.
  //
  // Both halves run in a CHILD with a timeout, so a regression FAILS within a bound instead of
  // hanging the suite that is supposed to report it.
  const root = await mkdtemp(join(tmpdir(), "noa-fifo-tree-"));
  try {
    const fifo = join(root, "pipe");
    execFileSync("mkfifo", [fifo]);

    // ANTI-VACUITY: a blocking open of this very FIFO really does hang.
    const blocking = `import { open } from "node:fs/promises";
      import { constants } from "node:fs";
      await open(${JSON.stringify(fifo)}, constants.O_RDONLY);
      console.log("OPENED");`;
    let blockingHung = false;
    try {
      execFileSync(process.execPath, ["--input-type=module", "-e", blocking],
        { encoding: "utf8", stdio: "pipe", timeout: 4000 });
    } catch (error) {
      blockingHung = error.killed === true || error.signal === "SIGTERM";
    }
    assert.equal(blockingHung, true,
      "a blocking open of a FIFO no longer waits — this regression has gone vacuous");

    // THE CONTROL: the attestation refuses the entry, promptly, instead of waiting on it.
    const attest = `import { dependencyTreeDigest } from ${JSON.stringify(join(PACKAGE_ROOT, "scripts", "apply-dependency-hardening.mjs"))};
      await dependencyTreeDigest(${JSON.stringify(root)});`;
    let refusal = null;
    let timedOut = false;
    try {
      execFileSync(process.execPath, ["--input-type=module", "-e", attest],
        { encoding: "utf8", stdio: "pipe", timeout: 8000 });
    } catch (error) {
      timedOut = error.killed === true || error.signal === "SIGTERM";
      refusal = String(error.stderr ?? "");
    }
    assert.equal(timedOut, false, "the attestation waited on a FIFO instead of rejecting it");
    assert.match(refusal ?? "", /non-regular entry/,
      "a FIFO was not rejected as a non-regular entry");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("an attestation refuses to run where O_NONBLOCK does not exist", () => {
  // Same fail-closed shape as O_NOFOLLOW: a flag that silently becomes zero would restore the
  // blocking open, and the attestation would hang rather than say it could not proceed safely.
  assert.equal(typeof nonBlockingOpenFlag(), "number", "this platform lost a working O_NONBLOCK");
  assert.notEqual(nonBlockingOpenFlag(), 0, "a zero flag would restore the blocking open");
  assert.throws(() => nonBlockingOpenFlag({}), /O_NONBLOCK is unavailable/);
  assert.throws(() => nonBlockingOpenFlag({ O_NONBLOCK: 0 }), /O_NONBLOCK is unavailable/);
});

test("an attestation refuses to run where O_NOFOLLOW does not exist", () => {
  // This flag was once computed as `fsConstants.O_NOFOLLOW ?? 0`. Zero is a NO-OP: on a platform
  // without the constant that expression produced an ordinary FOLLOWING open, while the code around
  // it and the commit describing it both claimed symlink safety. A control that silently becomes its
  // own absence is worse than no control, so the attestation refuses instead.
  assert.equal(typeof symlinkSafeOpenFlag(), "number", "this platform lost a working O_NOFOLLOW");
  assert.notEqual(symlinkSafeOpenFlag(), 0, "a zero flag would follow symlinks while claiming not to");
  assert.throws(() => symlinkSafeOpenFlag({}), /O_NOFOLLOW is unavailable/,
    "an absent O_NOFOLLOW was accepted, so the read could follow a link unnoticed");
  assert.throws(() => symlinkSafeOpenFlag({ O_NOFOLLOW: 0 }), /O_NOFOLLOW is unavailable/,
    "a zero O_NOFOLLOW was accepted, which is exactly the silent degradation this pins");
});

test("a linked install with no dependency tree is skipped by --apply and REFUSED by --check", async () => {
  // npm runs a linked package's postinstall where that package has no `node_modules` of its own.
  // MEASURED: `npm ci packages/e2e-demo` invoked this transformer against exactly that shape and the
  // ENOENT failed the whole install. Applying nothing there is honest; VERIFYING nothing is not, so
  // the two modes deliberately disagree — `--check` is the gate that the build depends on.
  const emptyRoot = await mkdtemp(join(tmpdir(), "noa-signer-linked-context-"));
  try {
    const applied = await hardenDependencies({ packageRoot: emptyRoot });
    assert.equal(applied.skipped, true, "--apply did not report that it transformed nothing");
    assert.equal(applied.changed, 0);
    assert.equal(applied.trees, 0);
    await assert.rejects(
      hardenDependencies({ checkOnly: true, packageRoot: emptyRoot }),
      /cannot be verified here/,
      "--check accepted a tree it could not see, which is the absence-as-success defect",
    );
  } finally {
    await rm(emptyRoot, { recursive: true, force: true });
  }
});

test("the package manifest pins every hardened dependency and its postinstall transformer", async () => {
  const manifest = JSON.parse(await readFile(join(PACKAGE_ROOT, "package.json"), "utf8"));
  assert.equal(manifest.private, true, "the unreleased signer package became publishable");
  assert.equal(
    manifest.publishConfig,
    undefined,
    "the unreleased signer package declares public publication intent",
  );
  assert.equal(
    manifest.scripts?.postinstall,
    "node scripts/apply-dependency-hardening.mjs --apply",
    "the installed artifact no longer applies the exact dependency transform",
  );
  assert.ok(
    manifest.files?.includes("scripts/apply-dependency-hardening.mjs"),
    "postinstall references a transformer excluded from the packed artifact",
  );
  assert.deepEqual(
    [...(manifest.bundledDependencies ?? [])].sort(),
    HARDENED_PACKAGE_NAMES,
    "the artifact may hoist or omit a dependency whose exact bytes the runtime requires",
  );
});

test("the extracted npm artifact carries the exact complete hardened dependency trees", async () => {
  const fixtureRoot = await mkdtemp(join(tmpdir(), "noa-signer-pack-attestation-"));
  try {
    // Write the real tarball outside the repository and inspect its extracted bytes. A dry-run file
    // list cannot prove the content of an unlisted executable inside a bundled dependency.
    const packed = JSON.parse(execFileSync(
      "npm",
      ["pack", "--json", "--ignore-scripts", "--pack-destination", fixtureRoot],
      { cwd: PACKAGE_ROOT, encoding: "utf8", maxBuffer: 8 * 1024 * 1024 },
    ));
    assert.equal(packed.length, 1, "npm pack did not produce exactly one signer artifact");
    const artifact = packed[0];
    const paths = new Set((artifact.files ?? []).map((file) => file.path));
    assert.ok(paths.has("scripts/apply-dependency-hardening.mjs"),
      "the actual pack file list omitted the postinstall transformer");
    assert.deepEqual([...(artifact.bundled ?? [])].sort(), HARDENED_PACKAGE_NAMES,
      "the actual pack metadata omitted or added a bundled dependency");
    for (const target of HARDENED_ARTIFACT_PATHS) {
      assert.ok(paths.has(target), `the actual pack file list omitted hardened target ${target}`);
    }

    const extracted = join(fixtureRoot, "extracted");
    await mkdir(extracted);
    execFileSync("tar", ["-xzf", join(fixtureRoot, artifact.filename), "-C", extracted]);
    const treeEvidence = await attestHardenedDependencyTrees({ packageRoot: join(extracted, "package") });
    assert.deepEqual(
      treeEvidence.map(({ packageName, files, sha256 }) => ({ packageName, files, sha256 })),
      HARDENED_PACKAGE_TREES.map(({ packageName, files, sha256 }) => ({ packageName, files, sha256 })),
      "the extracted artifact's complete dependency bytes differ from the clean reviewed trees",
    );
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
});

test("dependency hardening transform requires each exact anchor once", () => {
  const patch = {
    packageName: "fixture",
    relativePath: "fixture.js",
    replacements: [{ before: "unsafe", after: "isolated" }],
  };
  assert.equal(transformSource("before unsafe after", patch), "before isolated after");
  assert.throws(() => transformSource("before after", patch), /matched 0 times/);
  assert.throws(() => transformSource("unsafe unsafe", patch), /matched more than 1 times/);
});

test("dependency hardening expires closed before touching dependency state", async () => {
  await assert.rejects(
    hardenDependencies({
      checkOnly: true,
      packageRoot: "/path-that-must-not-be-read",
      now: Date.parse(HARDENING_POLICY.expiresAt),
    }),
    /expired after 2026-11-24/,
  );
});

test("dependency hardening rejects drift in patched and otherwise-unlisted bundled files", async () => {
  const fixtureRoot = await mkdtemp(join(tmpdir(), "noa-dependency-hardening-"));
  try {
    const fixtureScope = join(fixtureRoot, "node_modules", "@noble");
    await mkdir(fixtureScope, { recursive: true });
    for (const packageName of ["ciphers", "curves", "hashes"]) {
      await cp(
        join(PACKAGE_ROOT, "node_modules", "@noble", packageName),
        join(fixtureScope, packageName),
        { recursive: true },
      );
    }

    const clean = await hardenDependencies({ checkOnly: true, packageRoot: fixtureRoot });
    assert.deepEqual(
      { checked: clean.checked, changed: clean.changed },
      { checked: 7, changed: 0 },
      "the exact patched fixture did not verify as the reviewed transform set",
    );

    const unlisted = join(fixtureScope, "curves", "ed25519.js");
    const pristineUnlisted = await readFile(unlisted, "utf8");
    await writeFile(unlisted, `${pristineUnlisted}\n// diagnostic unlisted executable mutation\n`, "utf8");
    await assert.rejects(
      hardenDependencies({ checkOnly: true, packageRoot: fixtureRoot }),
      /@noble\/curves: complete dependency tree drift/,
      "an altered bundled executable outside the seven transforms was silently accepted",
    );
    await writeFile(unlisted, pristineUnlisted, "utf8");

    const drifted = join(fixtureScope, "ciphers", "_arx.js");
    await writeFile(drifted, `${await readFile(drifted, "utf8")}\n`, "utf8");
    await assert.rejects(
      hardenDependencies({ checkOnly: false, packageRoot: fixtureRoot }),
      /unknown bytes [0-9a-f]{64}/,
      "an unknown dependency byte change was silently rewritten or accepted",
    );
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
});
