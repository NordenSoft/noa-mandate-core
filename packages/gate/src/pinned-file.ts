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
 *   - With `checkAncestors`, the directory part is resolved once (`realpath`) and the final component
 *     is opened UNDER that resolved directory, so the path that is opened is exactly the chain the
 *     ancestor walk inspects. Every directory up to `/` must be owned by root or by the file's owner and
 *     carry no group/other write bit, unless it is root-owned and sticky (`/tmp`). A principal that can
 *     rename entries in any ancestor can replace the file without ever touching it.
 *
 * Nothing here parses content. Refusals are returned, never thrown, with one fixed leading token per
 * cause so a caller (and a test) can branch on the cause without reading prose.
 */

import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";
import { randomBytes } from "node:crypto";
import { describeThrown, thrownCode } from "noa-mcp-adapter-core/safe-throw";

export type PinnedFileToken =
  | "missing"
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
  /** Walk `realpath(dirname)` to `/` (see the file header). */
  readonly checkAncestors: boolean;
}

export type PinnedRead =
  | { readonly ok: true; readonly bytes: Uint8Array; readonly uid: number; readonly mode: number }
  | { readonly ok: false; readonly token: PinnedFileToken; readonly detail: string };

const O_NOFOLLOW = fsConstants.O_NOFOLLOW ?? 0;
const O_NONBLOCK = fsConstants.O_NONBLOCK ?? 0;

const octal = (mode: number): string => `0${(mode & 0o7777).toString(8)}`;

function fileRefusal(token: PinnedFileToken, detail: string): PinnedRead {
  return { ok: false, token, detail: `${token}: ${detail}` };
}

/**
 * Every directory from `dir` up to `/` must be owned by root or by `ownerUid`, and must not be writable
 * by group or others unless it is root-owned and sticky. `lstat`, so a component that became a symlink
 * after `realpath` is refused rather than followed. Returns a reason, or `null` when the chain is safe.
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

/** Read one operator-provisioned file under `policy`. Never throws. */
export function readPinnedFile(filePath: string, policy: PinnedReadPolicy): PinnedRead {
  let dir = dirname(filePath);
  let target = filePath;
  if (policy.checkAncestors) {
    try {
      dir = realpathSync(dir);
    } catch (err) {
      if (thrownCode(err) === "ENOENT") return fileRefusal("missing", `the directory of ${JSON.stringify(filePath)} does not exist`);
      return fileRefusal("unreadable", `cannot resolve the directory of ${JSON.stringify(filePath)} (${describeThrown(err)})`);
    }
    target = join(dir, basename(filePath));
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
    return { ok: true, bytes: new Uint8Array(buf.buffer, buf.byteOffset, size), uid: st.uid, mode: st.mode };
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
