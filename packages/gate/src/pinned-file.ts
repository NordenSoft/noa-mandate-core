/**
 * NOA Gate — ONE descriptor-based reader for operator-provisioned trust files, the parent-directory
 * walk, and the atomic state-file writer.
 *
 * WHO USES IT. The pinned roster (`noa.gate-roster/1`), the roster high-water state file, and the grant
 * sidecar's `--trust-file`. Each caller states its own POLICY (size cap, forbidden mode bits, owner
 * rule, link count, ancestor walk); the mechanics are shared so a hardening fix lands once.
 *
 * THE MECHANICS, and why each one exists:
 *   - ONE open, `O_RDONLY | O_NOFOLLOW | O_NONBLOCK`. `O_NOFOLLOW` makes a planted symlink at the final
 *     component fail the open itself; `O_NONBLOCK` makes a FIFO planted where the file is expected
 *     return at once instead of hanging the boot (the key-file loader measured that stall on
 *     2026-08-12); the regular-file test below then refuses it.
 *   - Every property is read from `fstat` on THAT descriptor, never from a second lookup of the path.
 *   - The bytes read must equal the size `fstat` reported: a file that grows or shrinks while it is
 *     read is refused (`short-read`), not half-trusted.
 *   - With `checkAncestors`, the CONFIGURED path must be absolute and free of `.`/`..` segments, and
 *     its directory part is resolved here, one component at a time with `lstat`. Every symlink met on
 *     the way (the configured path's own components and each link target's) is recorded with the
 *     directory that holds it; once the file's owner is known, each such link must be owned by root or
 *     that owner AND sit in a directory that passes the ancestor rule. Resolving with `realpath` and
 *     inspecting only the result let a symlink in a directory the gate's uid can write re-point the gate
 *     at a different, perfectly admin-owned roster (an archived one, say) without touching any file the
 *     walk looked at. The final component is opened UNDER the resolved directory, so the path that is
 *     opened is exactly the chain the ancestor walk inspects. Every directory of that chain up to `/`
 *     must be owned by root or by the file's owner and carry no group/other write bit, unless it is
 *     root-owned and sticky (`/tmp`). A principal that can rename entries in any ancestor can replace the
 *     file without ever touching it.
 *
 * Nothing here parses content. Refusals are returned, never thrown, with one fixed leading token per
 * cause so a caller (and a test) can branch on the cause without reading prose.
 */

import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  openSync,
  readlinkSync,
  readSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join } from "node:path";
import { randomBytes } from "node:crypto";
import { describeThrown, thrownCode } from "noa-mcp-adapter-core/safe-throw";

export type PinnedFileToken =
  | "missing"
  | "path-form"
  | "symlink-ancestor"
  | "symlink"
  | "unreadable"
  | "not-regular"
  | "nlink"
  | "size"
  | "mode"
  | "owner"
  | "ancestor"
  | "short-read";

export interface PinnedReadPolicy {
  /** Largest accepted file, in bytes. */
  readonly maxBytes: number;
  /** Mode bits that must all be clear: `0o022` (no group/other write) or `0o077` (owner only). */
  readonly forbiddenModeBits: number;
  /** Refuse a file with a second hard link: another name for the same bytes, in a directory this walk never saw. */
  readonly requireSingleLink: boolean;
  /** Owner rule; `null` = none. Returns true when the file's uid is acceptable. */
  readonly ownerAllowed: ((uid: number) => boolean) | null;
  /** Resolve the configured directory component by component, vet every symlink met, and walk the
   *  resolved directory to `/` (see the file header). Requires an absolute, `.`/`..`-free path. */
  readonly checkAncestors: boolean;
}

export type PinnedRead =
  | { readonly ok: true; readonly bytes: Uint8Array; readonly uid: number; readonly mode: number; readonly id: FileId }
  | { readonly ok: false; readonly token: PinnedFileToken; readonly detail: string };

/** A file's identity: the device and inode `fstat`/`lstat` report. A path can be re-pointed; this cannot. */
export interface FileId {
  readonly dev: number;
  readonly ino: number;
}
const sameFile = (a: FileId, b: { dev: number; ino: number }): boolean => a.dev === b.dev && a.ino === b.ino;

const O_NOFOLLOW = fsConstants.O_NOFOLLOW ?? 0;
const O_NONBLOCK = fsConstants.O_NONBLOCK ?? 0;

const octal = (mode: number): string => `0${(mode & 0o7777).toString(8)}`;

function fileRefusal(token: PinnedFileToken, detail: string): PinnedRead {
  return { ok: false, token, detail: `${token}: ${detail}` };
}

/**
 * Every directory from `dir` up to `/` must be owned by root or by `ownerUid`, and must not be writable
 * by group or others unless it is root-owned and sticky. `lstat`, so a component that became a symlink
 * after it was resolved is refused rather than followed. Returns a reason, or `null` when the chain is safe.
 */
export function unsafeAncestor(dir: string, ownerUid: number): string | null {
  let cur = dir;
  for (;;) {
    let st;
    try {
      st = lstatSync(cur);
    } catch (err) {
      return `cannot inspect ancestor directory ${JSON.stringify(cur)} (${describeThrown(err)})`;
    }
    if (!st.isDirectory()) return `ancestor ${JSON.stringify(cur)} is not a directory`;
    const rootSticky = st.uid === 0 && (st.mode & 0o1000) !== 0;
    if (st.uid !== 0 && st.uid !== ownerUid) {
      return `ancestor directory ${JSON.stringify(cur)} is owned by uid ${st.uid}, neither root nor the file's owner (uid ${ownerUid})`;
    }
    if ((st.mode & 0o022) !== 0 && !rootSticky) {
      return `ancestor directory ${JSON.stringify(cur)} is writable by group or others (mode ${octal(st.mode)})`;
    }
    const parent = dirname(cur);
    if (parent === cur) return null;
    cur = parent;
  }
}

/** A symlink met while resolving a configured directory, with the (resolved) directory that holds it. */
export interface ResolvedLink {
  readonly link: string;
  readonly container: string;
  readonly uid: number;
}

export type DirectoryResolution =
  | { readonly ok: true; readonly real: string; readonly links: readonly ResolvedLink[] }
  | { readonly ok: false; readonly token: PinnedFileToken; readonly detail: string };

/** POSIX's own bound on nested symlink expansion (Linux MAXSYMLINKS). */
const MAX_SYMLINK_EXPANSIONS = 40;

/** Non-empty components of a path, or `null` when a `.` or `..` segment appears. */
function segments(p: string): string[] | null {
  const out: string[] = [];
  for (const c of p.split("/")) {
    if (c === "") continue;
    if (c === "." || c === "..") return null;
    out.push(c);
  }
  return out;
}

/**
 * Resolve an absolute directory one component at a time with `lstat`, following symlinks by hand so
 * that every link — the configured path's own and those inside link targets — is RECORDED with the
 * resolved directory that holds it. A `.`/`..` segment in the configured path or in any link target is
 * refused: without it, every directory this resolution passes through is either on the final chain or
 * an ancestor of a recorded link's directory, and both are inspected. Never throws.
 */
export function resolveConfiguredDirectory(dir: string, configured: string = dir): DirectoryResolution {
  const refuse = (token: PinnedFileToken, detail: string): DirectoryResolution => ({ ok: false, token, detail: `${token}: ${detail}` });
  if (!isAbsolute(dir)) return refuse("path-form", `the configured path ${JSON.stringify(configured)} is not an absolute path`);
  let queue = segments(dir);
  if (queue === null) return refuse("path-form", `the configured path ${JSON.stringify(configured)} contains a . or .. segment`);
  let cur = "/";
  let expansions = 0;
  const links: ResolvedLink[] = [];
  while (queue.length > 0) {
    const c = queue.shift() as string;
    const next = cur === "/" ? `/${c}` : `${cur}/${c}`;
    let st;
    try {
      st = lstatSync(next);
    } catch (err) {
      if (thrownCode(err) === "ENOENT") return refuse("missing", `${JSON.stringify(next)} does not exist`);
      return refuse("unreadable", `cannot inspect ${JSON.stringify(next)} (${describeThrown(err)})`);
    }
    if (st.isSymbolicLink()) {
      expansions++;
      if (expansions > MAX_SYMLINK_EXPANSIONS) return refuse("symlink-ancestor", `more than ${MAX_SYMLINK_EXPANSIONS} symlinks while resolving ${JSON.stringify(dir)}`);
      let target: string;
      try {
        target = readlinkSync(next);
      } catch (err) {
        return refuse("unreadable", `cannot read the symlink ${JSON.stringify(next)} (${describeThrown(err)})`);
      }
      const targetSegments = segments(target);
      if (targetSegments === null) return refuse("symlink-ancestor", `the symlink ${JSON.stringify(next)} points through a . or .. segment`);
      links.push({ link: next, container: cur, uid: st.uid });
      if (isAbsolute(target)) cur = "/";
      queue = [...targetSegments, ...queue];
      continue;
    }
    if (!st.isDirectory()) return refuse("ancestor", `${JSON.stringify(next)} is not a directory`);
    cur = next;
  }
  return { ok: true, real: cur, links };
}

/**
 * Every recorded symlink must be owned by root or by the file's owner, and the directory holding it
 * must pass the ancestor rule. Returns a reason, or `null` when every link is the owner's own.
 */
export function unsafeLink(links: readonly ResolvedLink[], ownerUid: number): string | null {
  for (const l of links) {
    if (l.uid !== 0 && l.uid !== ownerUid) {
      return `the symlink ${JSON.stringify(l.link)} on the configured path is owned by uid ${l.uid}, neither root nor the file's owner (uid ${ownerUid})`;
    }
    const bad = unsafeAncestor(l.container, ownerUid);
    if (bad !== null) return `the symlink ${JSON.stringify(l.link)} on the configured path sits under an unsafe directory: ${bad}`;
  }
  return null;
}

/** Read one operator-provisioned file under `policy`. Never throws. */
export function readPinnedFile(filePath: string, policy: PinnedReadPolicy): PinnedRead {
  let dir = dirname(filePath);
  let target = filePath;
  let links: readonly ResolvedLink[] = [];
  if (policy.checkAncestors) {
    const base = basename(filePath);
    if (base === "" || base === "." || base === ".." || filePath.endsWith("/")) {
      return fileRefusal("path-form", `${JSON.stringify(filePath)} does not name a file`);
    }
    const resolved = resolveConfiguredDirectory(dir, filePath);
    if (!resolved.ok) return { ok: false, token: resolved.token, detail: resolved.detail };
    dir = resolved.real;
    links = resolved.links;
    target = join(dir, base);
  }

  let fd: number;
  try {
    fd = openSync(target, fsConstants.O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
  } catch (err) {
    const code = thrownCode(err);
    if (code === "ENOENT") return fileRefusal("missing", `${JSON.stringify(filePath)} does not exist`);
    if (code === "ELOOP") return fileRefusal("symlink", `${JSON.stringify(filePath)} is a symlink — refusing to follow it (CWE-367)`);
    return fileRefusal("unreadable", `${JSON.stringify(filePath)} could not be opened (${describeThrown(err)})`);
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) return fileRefusal("not-regular", `${JSON.stringify(filePath)} is not a regular file`);
    if (policy.requireSingleLink && st.nlink !== 1) {
      return fileRefusal("nlink", `${JSON.stringify(filePath)} has ${st.nlink} hard links; exactly one is required`);
    }
    if (st.size > policy.maxBytes) {
      return fileRefusal("size", `${JSON.stringify(filePath)} is ${st.size} bytes; the limit is ${policy.maxBytes}`);
    }
    if ((st.mode & policy.forbiddenModeBits) !== 0) {
      return fileRefusal("mode", `${JSON.stringify(filePath)} has mode ${octal(st.mode)}; bits ${octal(policy.forbiddenModeBits)} must be clear`);
    }
    if (policy.ownerAllowed !== null && !policy.ownerAllowed(st.uid)) {
      return fileRefusal("owner", `${JSON.stringify(filePath)} is owned by uid ${st.uid}, which this file's owner rule refuses`);
    }
    if (policy.checkAncestors) {
      const badLink = unsafeLink(links, st.uid);
      if (badLink !== null) return fileRefusal("symlink-ancestor", badLink);
      const bad = unsafeAncestor(dir, st.uid);
      if (bad !== null) return fileRefusal("ancestor", bad);
    }
    const size = st.size;
    const buf = Buffer.alloc(size + 1);
    let total = 0;
    for (;;) {
      const n = readSync(fd, buf, total, buf.length - total, null);
      if (n === 0) break;
      total += n;
      if (total > size) break;
    }
    if (total !== size) {
      return fileRefusal("short-read", `${JSON.stringify(filePath)}: read ${total} bytes where fstat reported ${size}; the file changed while it was read`);
    }
    return { ok: true, bytes: new Uint8Array(buf.buffer, buf.byteOffset, size), uid: st.uid, mode: st.mode, id: { dev: st.dev, ino: st.ino } };
  } catch (err) {
    return fileRefusal("unreadable", `${JSON.stringify(filePath)} could not be read (${describeThrown(err)})`);
  } finally {
    closeSync(fd);
  }
}

/**
 * Replace `filePath` atomically with `bytes`: a fresh temporary file opened
 * `O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW` at 0600 in the same directory, written, fsynced, renamed
 * over the target, then the directory fsynced so the rename itself is durable. The temporary name is
 * random, so a temporary file left by a crash can never block the next write. Never throws.
 */
export function writeFileAtomic(filePath: string, bytes: Uint8Array): { ok: true } | { ok: false; detail: string } {
  const dir = dirname(filePath);
  const tmp = join(dir, `.${basename(filePath)}.${randomBytes(8).toString("hex")}.tmp`);
  let fd: number | null = null;
  let renamed = false;
  try {
    fd = openSync(tmp, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | O_NOFOLLOW, 0o600);
    let off = 0;
    while (off < bytes.length) off += writeSync(fd, bytes, off, bytes.length - off);
    fsyncSync(fd);
    closeSync(fd);
    fd = null;
    renameSync(tmp, filePath);
    renamed = true;
    const dfd = openSync(dir, fsConstants.O_RDONLY);
    try {
      fsyncSync(dfd);
    } finally {
      closeSync(dfd);
    }
    return { ok: true };
  } catch (err) {
    if (fd !== null) {
      try {
        closeSync(fd);
      } catch {
        // the write already failed; the close result adds nothing
      }
    }
    if (!renamed) {
      try {
        unlinkSync(tmp);
      } catch {
        // nothing was created, or it is already gone
      }
    }
    return { ok: false, detail: `${JSON.stringify(filePath)} could not be written (${describeThrown(err)})` };
  }
}

/**
 * A lock file's identity: the device and inode `fstat` reports AND the file's exact bytes. Device and
 * inode alone are not an identity over time: Linux hands a freed inode number to the next file created
 * on that filesystem at once (measured on overlayfs, 20 of 20 unlink-then-create pairs; APFS, 0 of 20),
 * so a fresh lock created after a stale one was removed can carry the stale lock's device AND inode.
 * Every lock this module creates therefore carries a fresh random nonce, which makes its bytes differ
 * from every earlier lock's, and a lock matches only when device, inode and bytes all match.
 */
export interface LockIdentity {
  readonly id: FileId;
  readonly bytes: Uint8Array;
}
function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
const sameLock = (a: LockIdentity, b: LockIdentity): boolean => sameFile(a.id, b.id) && sameBytes(a.bytes, b.bytes);

/** How a lock file is read back: no symlink, a regular 0600-style file, one link, small. */
const LOCK_READ_POLICY: PinnedReadPolicy = { maxBytes: 64, forbiddenModeBits: 0o022, requireSingleLink: true, ownerAllowed: null, checkAncestors: false };

/** The identity of the lock file at `lockPath` now, or `null` when it cannot be read as one. */
function readLockIdentity(lockPath: string): LockIdentity | null {
  const r = readPinnedFile(lockPath, LOCK_READ_POLICY);
  return r.ok ? { id: r.id, bytes: r.bytes } : null;
}

/**
 * An exclusive lock file: created `O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW` at 0600 and holding the
 * creating process's pid and a fresh random nonce (`<pid>\n<32 hex>\n`). Existence IS the lock.
 * `release` removes ONLY the lock this attempt created (same device, inode AND bytes): if the path now
 * names another boot's lock, even one that reuses this lock's inode number, that lock is left alone.
 * When the file already exists its holder's pid and identity are returned, so the caller can decide
 * whether the holder is alive and take a dead holder's lock over by identity. A holder file of the
 * older `<pid>\n` form is still read. Never throws.
 */
export type LockAttempt =
  | { readonly ok: true; release(): void }
  | { readonly ok: false; readonly kind: "held"; readonly holderPid: number | null; readonly holderIdentity: LockIdentity | null; readonly detail: string }
  | { readonly ok: false; readonly kind: "unwritable"; readonly detail: string };

export function tryCreateLock(lockPath: string): LockAttempt {
  let fd: number;
  try {
    fd = openSync(lockPath, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | O_NOFOLLOW, 0o600);
  } catch (err) {
    if (thrownCode(err) === "EEXIST") {
      const holder = readLockHolder(lockPath);
      return { ok: false, kind: "held", holderPid: holder?.pid ?? null, holderIdentity: holder?.identity ?? null, detail: `${JSON.stringify(lockPath)} exists` };
    }
    return { ok: false, kind: "unwritable", detail: `${JSON.stringify(lockPath)} could not be created (${describeThrown(err)})` };
  }
  let own: LockIdentity;
  try {
    const bytes = new TextEncoder().encode(`${process.pid}\n${randomBytes(16).toString("hex")}\n`);
    const st = fstatSync(fd);
    own = { id: { dev: st.dev, ino: st.ino }, bytes };
    writeSync(fd, bytes);
    fsyncSync(fd);
  } catch (err) {
    closeSync(fd);
    try {
      unlinkSync(lockPath);
    } catch {
      // the lock was never usable; nothing else to undo
    }
    return { ok: false, kind: "unwritable", detail: `${JSON.stringify(lockPath)} could not be written (${describeThrown(err)})` };
  }
  closeSync(fd);
  let released = false;
  return {
    ok: true,
    release(): void {
      if (released) return;
      released = true;
      try {
        // Only the lock this attempt created: after a takeover race the path may name another boot's
        // live lock, even under this lock's recycled inode number, and deleting THAT would let a third
        // boot in.
        const now = readLockIdentity(lockPath);
        if (now !== null && sameLock(own, now)) unlinkSync(lockPath);
      } catch {
        // already gone: an administrator removed it, and the next holder will re-check the state
      }
    },
  };
}

const isDigits = (s: string): boolean => {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x30 || c > 0x39) return false;
  }
  return s.length > 0;
};
const isNonce = (s: string): boolean => {
  if (s.length !== 32) return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (!((c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66))) return false;
  }
  return true;
};

/**
 * The pid and identity of an existing lock file, or `null` when it cannot be read as one: `<pid>` on
 * the first line, optionally followed by one line holding a 32-hex nonce, and nothing else.
 */
function readLockHolder(lockPath: string): { pid: number; identity: LockIdentity } | null {
  const identity = readLockIdentity(lockPath);
  if (identity === null) return null;
  const lines = new TextDecoder().decode(identity.bytes).trim().split("\n");
  if (lines.length > 2) return null;
  const pidText = lines[0]!.trim();
  if (!isDigits(pidText) || pidText.length > 10) return null;
  if (lines.length === 2 && !isNonce(lines[1]!.trim())) return null;
  const pid = Number(pidText);
  return pid > 0 ? { pid, identity } : null;
}

/**
 * Take over a lock whose holder was found DEAD, atomically: rename it aside under a unique name, then
 * check that the file now aside IS the one that was read (same device, inode AND bytes). Only then is
 * it deleted. If it is not — another boot replaced the stale lock with its own live one between our
 * read and our rename, possibly under the stale lock's recycled inode number — it is put back (a hard
 * link, which never overwrites a newer lock) and the takeover reports "changed". Removing the stale
 * lock by PATH instead let two boots that both saw the dead holder each delete the other's fresh lock
 * and both proceed. Never throws.
 */
export function takeOverStaleLock(lockPath: string, expected: LockIdentity): "taken" | "gone" | "changed" {
  const aside = `${lockPath}.stale-${randomBytes(8).toString("hex")}`;
  try {
    renameSync(lockPath, aside);
  } catch (err) {
    return thrownCode(err) === "ENOENT" ? "gone" : "changed";
  }
  const moved = readLockIdentity(aside);
  if (moved !== null && sameLock(expected, moved)) {
    try {
      unlinkSync(aside);
    } catch {
      // the stale lock is already out of the way under its unique name
    }
    return "taken";
  }
  try {
    linkSync(aside, lockPath);
  } catch {
    // a newer lock already holds the path; the directory stays locked by it
  }
  try {
    unlinkSync(aside);
  } catch {
    // nothing further to undo
  }
  return "changed";
}
