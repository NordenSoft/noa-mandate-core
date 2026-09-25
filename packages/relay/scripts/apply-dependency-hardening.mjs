#!/usr/bin/env node
/**
 * The relay's @noble dependency trees, hardened by the SAME reviewed mechanism as signer-core's.
 *
 * The relay only verifies Ed25519 signatures and holds no secret, so signer-core's state-isolation
 * patches do not change anything the relay computes. They are applied here anyway so the repository
 * carries ONE reviewed set of @noble bytes instead of two: this package installs exactly the three
 * packages and versions signer-core pins, and this file hands the relay's own node_modules to
 * signer-core's transformer and complete-tree attestation. Nothing is re-implemented or re-pinned
 * here — the patches, the before/after hashes and the three complete-tree digests are imported — so a
 * @noble version that moves in one package and not in the other is refused by this check.
 *
 * `@noble/ciphers` is not imported by the relay. It is installed because the attestation covers all
 * three trees and a partial attestation is a refusal, never a pass.
 */
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { hardenDependencies } from "../../signer-core/scripts/apply-dependency-hardening.mjs";

const RELAY_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const mode = process.argv.slice(2);
if (mode.length !== 1 || (mode[0] !== "--apply" && mode[0] !== "--check")) {
  console.error("usage: node scripts/apply-dependency-hardening.mjs <--apply|--check>");
  process.exitCode = 1;
} else {
  const checkOnly = mode[0] === "--check";
  try {
    const result = await hardenDependencies({ checkOnly, packageRoot: RELAY_ROOT });
    console.log(result.skipped === true
      ? `dependency hardening skipped: no dependency tree beside the relay, nothing to apply, ${result.policyId}`
      : `relay dependency hardening ${checkOnly ? "verified" : "applied"}: ${result.checked}/${result.checked} exact patches, ` +
        `${result.trees}/${result.trees} complete package trees, ${result.changed} changed, ${result.policyId}`,
    );
  } catch (error) {
    console.error(`relay dependency hardening failed: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}
