# Pinned trust for the reference gate (`noa.gate-roster/1`)

Status: reference-gate configuration for `packages/gate`. It is not wire language, it is not part of
`noa.receipt/0.1` or of any side-artifact schema, and no interoperability or conformance claim is
made for it: the format is exercised by the gate's own unit tests only, and no conformance corpus is
published. What pinned trust does **not** establish is listed in [NON-CLAIMS.md](../NON-CLAIMS.md)
§S8.

## Why

Without pinned trust, `noa-gate serve` builds a fresh trust root on every boot: a new root, authority
and gate key, a self-signed delegation and a self-signed key manifest. The process that authorizes
effects is then also the source of the trust material saying it may. The approver key comes from
environment variables. Because `POST /v1/holds/:id/decision` is authorized by its signature alone,
whoever controls that trust material authorizes every effect.

A pinned gate instead:

- loads a **persistent gate key** from a file it never creates;
- takes the approver, the audit recipient, the key-manifest epoch and the quorum **only** from a
  roster file on the gate host;
- checks every decision against that epoch, its own audience and the sealed display's recipients;
- seals every display with the real HPKE sealer (`noa-signer`);
- never falls back to the self-minted alpha root. Every failure refuses the boot.

## Selecting the mode

Pinned mode is selected when **any** of these variables is present. An empty value counts as present.

| Variable | Meaning |
| --- | --- |
| `NOA_GATE_ROSTER_FILE` | Absolute path of the roster, with no `.` or `..` segments. Required in pinned mode. |
| `NOA_GATE_KEY_FILE` | Path of the gate key file. Required in pinned mode. |
| `NOA_GATE_ROSTER_SHA256` | Optional second-channel pin: `sha256:<64 lowercase hex>`, compared exactly with the roster digest. |
| `NOA_GATE_UNSAFE_ROSTER_SAME_UID` | `1` accepts a roster owned by the gate's own uid, and a gate running as root. Development only; the banner says `SAME-UID (unsafe)` or `ROOT-GATE (unsafe)`. |

With none of them present the gate runs in `ALPHA-EPHEMERAL` mode, unchanged apart from its banner.
Alpha wires **no display sealer**, so every alpha hold is refused with
`500 DISPLAY_SEALER_UNCONFIGURED`. This is deliberate. Alpha discards the approver's HPKE private
half when it generates it, so an alpha display could be opened by nobody, while the approver key
from the environment could still sign a decision for it.

In pinned mode, `NOA_GATE_BIND`, `NOA_GATE_PORT`, `NOA_GATE_GRANT_SIGNER_SOCKET` and
`NOA_GATE_UNSAFE_IN_PROCESS_GRANT_KEY` keep their meaning. `NOA_GATE_TENANT`, when set, must equal
the roster's tenant. Any `NOA_GATE_APPROVER_*`, `NOA_GATE_GRANT_SIGNER_KID` or
`NOA_GATE_GRANT_SIGNER_PUBLIC_KEY` is refused, not ignored: the roster is the only source of
identities.

## The roster

```json
{
  "spec": "noa.gate-roster/1",
  "tenant": "tenant-example-1",
  "rosterVersion": 3,
  "validFrom": "2026-09-01T00:00:00Z",
  "expiresAt": "2026-10-01T00:00:00Z",
  "epoch": { "keyManifestVersion": 2, "keyManifestHash": "sha256:<64 lowercase hex>" },
  "gate": { "kid": "gate-example-1", "publicKey": "<base64 DER SPKI Ed25519>" },
  "executionSigner": null,
  "approvers": {
    "approver-example-1": {
      "role": "approve-critical",
      "publicKey": "<base64 DER SPKI Ed25519>",
      "hpkePublicKey": "<base64 DER SPKI X25519>",
      "validFrom": "2026-09-01T00:00:00Z",
      "revokedAt": null
    }
  },
  "audit": { "kid": "audit-example-1", "hpkePublicKey": "<base64 DER SPKI X25519>" },
  "quorum": { "HIGH": 1, "CRITICAL": 1 }
}
```

Every member is required and the member set is closed at every level. An undefined member, including
`sig`, is refused.

- **Kids** (gate, execution signer, approvers, audit): 1-64 characters from `[a-z0-9-]`, starting with
  `[a-z]` and ending with `[a-z0-9]`.
- **Tenant:** 1-256 printable ASCII characters (0x21-0x7E).
- **`rosterVersion` and `epoch.keyManifestVersion`:** safe integers ≥ 1.
  **`epoch.keyManifestHash`:** `sha256:` followed by 64 lowercase hex characters.
- **Times:** RFC 3339 instants, read under the key-manifest schema's grammar with nanosecond
  precision (never `Date.parse`). `revokedAt` is `null` or an instant.
- **Ed25519 keys:** accepted exactly when the decision verifier would accept them
  (`isStrictEd25519PublicKey`): canonical base64, canonical DER, canonical y, a y that decodes to a
  point on the curve, no x = 0 point spelled with the sign bit set (RFC 8032 §5.1.3), and not
  small-order.
- **X25519 keys:** canonical base64 of a 44-byte DER SubjectPublicKeyInfo of type `x25519` that
  re-encodes byte for byte, whose u-coordinate is a canonical field element (bit 255 clear, u < p).
  RFC 7748 decoding masks bit 255 and reduces mod p, so any other spelling is the same key under a
  second string, which the string-based reuse check below would not see. The raw-hex spelling is
  refused, and so is a low-order point (the display sealer can never seal to one, so the gate would
  boot and then fail every hold).
- **Role:** `approve-high` or `approve-critical`.
- **Quorum:** a non-empty object keyed by risk class (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`,
  `IRREVERSIBLE`). Each value is an integer ≥ 1. This version implements exactly 1, so a value of 2
  or more is refused, never treated as 1.
- **Across members:**
  - no kid appears twice;
  - no Ed25519 key appears under two identities (gate, execution signer, approvers);
  - no X25519 key appears under two identities (approvers, audit);
  - exactly one approver is active (`revokedAt: null`);
  - `validFrom < expiresAt`;
  - the active approver's role clears every class the quorum names (`requiredApproverRole`, the
    verifier's own lattice).
- **At load, by the gate's clock:**
  - the roster is within its validity window;
  - the window is at most 90 days;
  - the active approver's `validFrom` has passed;
  - no `revokedAt` is in the future. A revocation takes effect when the roster is loaded.

The **roster digest** is `"sha256:" + hex(SHA-256(JCS(roster)))` over the parsed value, so
whitespace, key order and escape spelling do not change it. The boot banner and `roster-check` both
print it.

### How the roster is authenticated in /1

The roster is not signed. It is trusted because of three things:

1. **File discipline, checked mechanically.**
   - The file is opened once with `O_RDONLY | O_NOFOLLOW | O_NONBLOCK` and inspected with `fstat` on
     that descriptor.
   - It must be a regular file with exactly one hard link and at most 64 KiB. The bytes read must
     equal the size `fstat` reported.
   - It must not be writable by group or others.
   - It must be owned by root, or by a uid **other than the gate's effective uid**. A roster the
     gate's own uid can rewrite could be rewritten by a compromised gate, or by an agent sharing its
     uid, and would survive a restart.
   - The configured path must be absolute and free of `.` and `..` segments, and so must every symlink
     target met while resolving it (a relative target such as `../archive` or `./admin` is refused
     with `symlink-ancestor`). Its directory is resolved
     one component at a time with `lstat`. Every symlink met on the way (in the configured path or
     inside a link target) must be owned by root or by the roster's owner, and every directory above
     it must pass the rule below. A symlink in a directory the gate can write would otherwise re-point
     the gate at a different, perfectly admin-owned roster, such as an archived one. A root-owned
     platform link such as macOS `/var -> /private/var` passes.
   - Every directory of the resolved chain up to `/` must be owned by root or by the roster's owner,
     and must not be writable by group or others, unless it is root-owned and sticky.
   - The gate must not run as root (`PINNED_ROOT_GATE`): root can rewrite any roster, so the owner rule
     would certify nothing. Run the gate as a dedicated non-root uid.
   - Mode bits and ownership are what is inspected. An access-control list that grants write outside
     the mode bits is not read: on Linux a named-user or named-group write entry raises the group
     write bit and is refused, but an extended ACL on macOS does not change the mode and is not seen.
2. **The digest in the boot banner**, for comparison with the value `roster-check` printed when the
   roster was written.
3. **The optional second-channel pin** `NOA_GATE_ROSTER_SHA256`, checked before any semantic rule.

A signed renewal is future work (`/2`).

## The gate key file

The key file has the shape `{ "kid", "privateKey": "<base64 PKCS8>", "publicKey": "<base64 SPKI>" }`.
It is loaded by the shared key-file loader, which requires:

- `O_NOFOLLOW` and `O_NONBLOCK` on the open;
- a regular file;
- ownership by the gate's uid or root;
- no group or other mode bits.

`serve` never creates a key file: a missing file is `GATE_KEY_FILE_MISSING`. After loading, the kid
must satisfy the kid rule, the private key must be Ed25519, and its public half must equal
`publicKey`. Otherwise the result is `GATE_KEY_INCONSISTENT`. Finally, `{kid, publicKey}` must equal
the roster's `gate` member, or the result is `GATE_KEY_NOT_PINNED`.

`noa-gate keygen --key-file <path> --kid <kid>` is the only minting path:

- it creates the file exclusively, with mode 0600;
- if the file already exists it reads it and never overwrites it;
- it exits 1 if the existing file holds another kid;
- it prints the roster's `gate` member and never prints the private key.

## The high-water state file

The state file is `<NOA_GATE_KEY_FILE>.roster-state`:

```json
{"rosterDigest":"sha256:…","rosterVersion":3,"spec":"noa.gate-roster-state/1"}
```

It follows the key file's owner rule: the gate's uid or root, no group or other bits, one hard link.

The read, the comparison and the write happen under one exclusive lock,
`<NOA_GATE_KEY_FILE>.roster-state.lock`. The lock is created `O_EXCL | O_NOFOLLOW` at mode 0600 and
holds the booting process's pid. A second boot on the same key file while a live process holds the lock
is `STATE_LOCKED`. A lock whose holder has died is taken over once, by identity: it is renamed aside
and deleted only if it is the same file (device and inode) that was read, and otherwise put back and
refused `STATE_LOCKED`. A boot releases only the lock file it created. A lock that names no readable
pid is `STATE_LOCKED` until an administrator removes it. The key file's directory must be writable by
the gate, because the lock and the state file live there; if it is not, the boot is refused with
`STATE_DIR_NOT_WRITABLE`. At commit the state is read and
compared again under the lock, so a floor written in the meantime by anything that ignores the lock
is never lowered.

| State file shows | Roster loaded | Result |
| --- | --- | --- |
| Nothing (file missing) | Any | First boot; banner shows `rosterHighWater: "INITIALIZED"` |
| Version N | Lower version | `ROSTER_ROLLBACK` |
| Version N | Same version, different digest | `ROSTER_EQUIVOCATION` |
| Version N | Same version, same digest | `UNCHANGED` |
| Version N | Higher version | `ADVANCED` |

The file is written only after every other check has passed and before the gate listens. The write
uses a fresh randomly named temporary file (`O_EXCL | O_NOFOLLOW`, mode 0600), which is written,
fsynced and renamed over the target, and then the directory is fsynced.

## Load order and refusal codes

The first failure wins. Every code exits 1 before the gate listens, printing
`noa-gate: <CODE>: <detail>` on stderr. There is no retry and no fallback.

| Stage | Check | Codes |
| --- | --- | --- |
| 0 | Platform | `PINNED_PLATFORM_UNSUPPORTED` (no POSIX uids) |
| 1 | Environment | `CONFIG_PINNED_INCOMPLETE`, `CONFIG_SOURCE_CONFLICT` |
| 2 | Gate uid, then roster file | `PINNED_ROOT_GATE`; `ROSTER_FILE_MISSING`, `ROSTER_FILE_UNSAFE`. The detail starts with one of `path-form`, `symlink-ancestor`, `symlink`, `not-regular`, `nlink`, `size`, `mode`, `owner`, `ancestor`, `short-read`, `unreadable`. |
| 3 | Parse | `ROSTER_PARSE`, `ROSTER_NOT_OBJECT` |
| 4 | Digest pin | `ROSTER_DIGEST_MISMATCH` |
| 5 | Members, then closed world | `ROSTER_SPEC_UNSUPPORTED`; then, in JCS key order, `ROSTER_MEMBER_INVALID`, `ROSTER_KID_INVALID`, `ROSTER_KEY_INVALID`, `ROSTER_HPKE_KEY_INVALID`, `ROSTER_ROLE_INVALID`, `ROSTER_TIME_INVALID`, `ROSTER_EPOCH_INVALID`, `ROSTER_QUORUM_INVALID`, `QUORUM_UNSUPPORTED`, `ROSTER_VERSION_INVALID`, `ROSTER_TENANT_INVALID`; then `ROSTER_UNRECOGNIZED_MEMBER` |
| 6 | Across members | `ROSTER_DUPLICATE_KID`, `ROSTER_KEY_REUSE`, `ROSTER_NO_ACTIVE_APPROVER`, `ROSTER_APPROVER_COUNT_UNSUPPORTED`, `ROSTER_TIME_INVALID`, `ROSTER_ROLE_INSUFFICIENT` |
| 7 | Tenant | `CONFIG_SOURCE_CONFLICT` (`NOA_GATE_TENANT` differs from the roster) |
| 8 | Clock | `ROSTER_NOT_YET_VALID`, `ROSTER_EXPIRED`, `ROSTER_VALIDITY_TOO_LONG`, `ROSTER_APPROVER_NOT_YET_VALID`, `ROSTER_TIME_INVALID` (future revocation) |
| 9 | Key file | `GATE_KEY_FILE_MISSING`, `GATE_KEY_FILE_UNSAFE`, `GATE_KEY_INCONSISTENT`, `GATE_KEY_NOT_PINNED` |
| 10 | Signer posture | `ROSTER_EXEC_SIGNER_MISMATCH`: the roster's `executionSigner` is null exactly when `NOA_GATE_GRANT_SIGNER_SOCKET` is set, or the other way round |
| 11 | State | `STATE_DIR_NOT_WRITABLE`, `STATE_LOCKED`, `STATE_FILE_UNSAFE`, `STATE_FILE_CORRUPT`, `ROSTER_ROLLBACK`, `ROSTER_EQUIVOCATION`; at commit, the same comparison again, then `STATE_FILE_WRITE_FAILED` |

When the roster pins an `executionSigner`, the out-of-process signer's expected identity is taken
from the roster. The in-process grant key still requires `NOA_GATE_UNSAFE_IN_PROCESS_GRANT_KEY=1`.

## What the running gate checks

These checks run in both modes. Each one is load-bearing only where a hold store outlives a trust
root, or is shared between trust roots: a durable store, or a restart onto one. With the in-memory
store, a restart already loses every hold.

The ownership check (audience and epoch) runs before any signature or state change on an existing
hold or grant. That covers `decide`, `reserve`, `cancel` and `report`, and the expiry and uncertainty
sweeps, which leave a hold or grant this trust root does not own exactly as it is. In `decide` it runs
before a hold is lazily expired, so a foreign gate never signs a timeout receipt for another gate's
hold.

| Where | Check | Refusal |
| --- | --- | --- |
| `decide`, `reserve`, `cancel`, `report` | The hold envelope names this gate's tenant and gate kid | `409 GATE_AUDIENCE_MISMATCH` |
| `decide`, `reserve`, `cancel`, `report` | The hold envelope carries this trust root's key-manifest epoch | `409 EPOCH_CHANGED` |
| `decide`, after signature verification | The deciding approver is a recipient of the hold's sealed display | `422 APPROVER_NOT_DISPLAY_RECIPIENT` |
| `createHold`, on egress from the sealer | The requested recipients are distinct, and the sealed display's recipients are exactly that set: no extra, no missing | `422 DISPLAY_EGRESS_AAD_MISMATCH` |

These checks run in pinned mode only:

| Where | Check | Refusal |
| --- | --- | --- |
| `createHold`, `decide`, `reserve` | The gate's clock is before the roster's `expiresAt` | `503 ROSTER_EXPIRED` |
| `createHold`, `decide` | The hold's risk class is named in the roster's quorum | `422 RISK_CLASS_NOT_IN_ROSTER` |
| `createHold`, `decide` | The quorum value for that class is 1 | `500 QUORUM_UNSUPPORTED` |

A refusal at `decide` leaves the hold `PENDING`, and it expires normally. Quorum comes only from the
roster: a decision body is read only for its `receipt` and `decisionArtifact`. A grant's signed
`expiresAt` is clamped to the roster's `expiresAt` as well as to the hold's life.

Roster expiry stops AUTHORITY, not RECORDING. After the roster expires the gate freezes no hold,
decides nothing (it refuses before it touches the hold) and reserves nothing. It still records what
follows from authority given before expiry: a timeout for an overdue hold, a cancellation that closes
a hold, an execution reported for a grant, and an uncertainty for a stuck one. Otherwise the evidence
of something that already happened would be lost.

The audience check and the display-recipient check compare kids. A kid reused for a new key would pass
both, which is why a kid is never reused for a new key. That is an operator rule; it is not enforced
across rosters.

`reserve` re-runs the audience, epoch and roster-expiry checks, but this has a limit. `GET` and
`wait` already hand the signed grant to the agent that owns the hold, so the reserve checks stop only
a wrapper that asks before it acts. A single-use commit at the effect owner is separate work.

`POST /v1/holds` returns the sealed display (`encryptedDisplay`) next to the hold envelope whose
`displayCiphertextHash` binds it. The display is ciphertext, readable only by the approver and audit
recipients.

## Command line

- `noa-gate` or `noa-gate serve` starts the gate. In pinned mode the banner reports:
  - `trustMode`, `rosterDigest`, `rosterVersion`, `rosterHighWater`, `rosterExpiresAt`,
    `rosterCustody`;
  - `epoch`, `gateKid`, `gatePublicKey`, `executionSignerKid`, `grantKeyCustody`;
  - `activeApproverKid`, `quorum`, `bootId`, `displaySealer: "hpke"`.
- `noa-gate keygen --key-file <path> --kid <kid>` creates the gate key; see above.
- `noa-gate roster-check <roster> [--key-file <path>]` validates a roster under the same environment
  rules `serve` applies, so a second identity source is `CONFIG_SOURCE_CONFLICT` here too. It prints
  the digest and a summary. With `--key-file` it also checks the key file and the high-water state,
  reading them without taking the lock. It never writes and never listens. Run it as the gate's OS
  user, because the owner rule is evaluated against the caller's uid.
- Any other subcommand exits 2 with `UNKNOWN_SUBCOMMAND` and starts nothing. Every subcommand refuses
  an argument it does not know with `UNKNOWN_ARGUMENT` (exit 2); `serve` takes no arguments at all.

## Lifecycle

- **Restart.** The same key file keeps the gate kid and key; `bootId` changes. The roster and the
  state are read again and the digest is printed again. In-flight holds in the in-memory store are
  lost (`404 UNKNOWN_HOLD`, no grant). There is no hot reload: one roster and one epoch per process.
- **Rotation.** Every rotation is a roster edit with `rosterVersion + 1`, followed by a restart.
  - Gate key: run `keygen` for a new file with a new kid, publish a new roster, restart. Approver
    devices refuse the new key until they learn it; that is a denial of service, not a safety failure.
  - Approver: set `revokedAt` on the old entry and add the new active entry.
  - Audit key: displays sealed earlier still need the old audit private key, kept offline.
  - Epoch: change it when the approver devices' key manifest changes.
- **Revocation.** A non-null `revokedAt` is refused by the decision verifier, retired in the receipt
  keyring, and never used as a sealing recipient. It takes effect at restart. Rolling it back is
  `ROSTER_ROLLBACK`.
- **Recovery.**
  - Lost approver device: revoke its entry.
  - Lost key file: new key and new roster.
  - Corrupt roster or state file: boot is refused; an administrator restores it with a version
    bump. Deleting the state file by hand shows `INITIALIZED` in the next banner.
- **Downgrade.**
  - Pinned mode never falls back to alpha. Going from pinned to alpha needs every pinned variable
    removed, and the banner then says `ALPHA-EPHEMERAL`.
  - A `/1` gate refuses a `/2` roster.
  - A quorum of 2 or more is refused.
- **Clock and offline limits.**
  - The gate's clock is the only authority: at load, at `createHold`, `decide` and `reserve`, and for
    the approval window and grant life. A clock rollback is not detected.
  - `expiresAt` is mandatory and capped at 90 days. After it the gate authorizes nothing until an
    administrator provides a new roster and the gate restarts.

## What the knockout registry does not measure

Every control above has a knockout arm whose detecting test asserts the attack's consequence (a
grant, a hold, a boot, the key file's bytes), not only a refusal code. These three rules have no arm,
because removing any one of them changes only which refusal an input gets, never whether it is
refused:

- The `.`/`..` segment and absolute-path rule of the configured roster path. Without it, a dot-segment
  path still resolves to a missing or refused file in every case the tests could build. Its purpose is
  to keep the symlink walk's inspected set complete.
- The roster's class-membership line at `createHold` and `decide`. The quorum-value line refuses the
  same input, and the whole check is armed as one control.
- The zero-active-approver branch. Removing it crashes the loader, which still refuses.

## The grant sidecar's trust file

The sidecar's `--trust-file` is read by the same descriptor reader. It gained `O_NONBLOCK` and a
1 MiB size cap; its owner policy is unchanged (no owner rule, group read allowed). It remains a
separate file from the roster. Drift between the two fails closed.
