import { createHash } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
} from "node:fs";
import { types as utilTypes } from "node:util";
import * as zlib from "node:zlib";

const TAR_BLOCK = 512;
const MAX_COMPRESSED_BYTES = 64 * 1024 * 1024;
const MAX_UNCOMPRESSED_BYTES = 256 * 1024 * 1024;
const MAX_ENTRY_BYTES = 32 * 1024 * 1024;
const MAX_ENTRIES = 20_000;
const MAX_CANONICAL_JSON_DEPTH = 64;
// npm's pinned tar implementation emits its reproducible 1985-10-26T08:15:00Z timestamp.
const CANONICAL_NPM_TAR_MTIME = 499_162_500;
const FORBIDDEN_PATH_CHARS_RE = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u;
const UTF8 = new TextDecoder("utf-8", { fatal: true });
const CANONICAL_GZIP_HEADER = Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff]);
const GZIP_HEADER_BYTES = CANONICAL_GZIP_HEADER.length;
const GZIP_TRAILER_BYTES = 8;
const GZIP_CAPABILITIES = Object.freeze({ crc32: zlib.crc32, gunzipSync: zlib.gunzipSync });

export class TarballValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "TarballValidationError";
  }
}

export function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export function bytewiseCompare(left, right) {
  return Buffer.from(left, "utf8").compare(Buffer.from(right, "utf8"));
}

function canonicalValue(value, depth = 0, ancestors = new WeakSet()) {
  if (depth > MAX_CANONICAL_JSON_DEPTH) {
    throw new TarballValidationError(
      `canonical JSON exceeds ${MAX_CANONICAL_JSON_DEPTH} nested container levels`,
    );
  }
  if (value === null || typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new TarballValidationError(`canonical JSON refuses non-integer number ${String(value)}`);
    }
    return value;
  }
  if (typeof value === "object") {
    if (utilTypes.isProxy(value)) {
      throw new TarballValidationError("canonical JSON refuses Proxy input");
    }
    if (ancestors.has(value)) {
      throw new TarballValidationError("canonical JSON refuses cyclic input");
    }
    ancestors.add(value);
    try {
      const descriptors = Object.getOwnPropertyDescriptors(value);
      const descriptorKeys = Reflect.ownKeys(descriptors);
      if (descriptorKeys.some((key) => typeof key === "symbol")) {
        throw new TarballValidationError("canonical JSON refuses symbol-keyed properties");
      }
      if (Array.isArray(value)) {
        if (Object.getPrototypeOf(value) !== Array.prototype) {
          throw new TarballValidationError("canonical JSON refuses non-plain arrays");
        }
        const lengthDescriptor = descriptors.length;
        const length = lengthDescriptor !== undefined && "value" in lengthDescriptor
          ? lengthDescriptor.value
          : null;
        if (
          !Number.isSafeInteger(length) || length < 0 ||
          descriptorKeys.length !== length + 1
        ) {
          throw new TarballValidationError(
            "canonical JSON refuses sparse arrays and named array properties",
          );
        }
        const out = new Array(length);
        for (let index = 0; index < length; index++) {
          const descriptor = descriptors[String(index)];
          if (
            descriptor === undefined || descriptor.enumerable !== true ||
            !("value" in descriptor)
          ) {
            throw new TarballValidationError(
              "canonical JSON refuses sparse arrays and accessor elements",
            );
          }
          out[index] = canonicalValue(descriptor.value, depth + 1, ancestors);
        }
        return out;
      }
      const prototype = Object.getPrototypeOf(value);
      if (prototype !== Object.prototype && prototype !== null) {
        throw new TarballValidationError("canonical JSON refuses non-plain objects");
      }
      const keys = descriptorKeys.sort(bytewiseCompare);
      const out = Object.create(null);
      for (const key of keys) {
        const descriptor = descriptors[key];
        if (
          descriptor === undefined || descriptor.enumerable !== true ||
          !("value" in descriptor)
        ) {
          throw new TarballValidationError(
            "canonical JSON refuses non-enumerable or accessor object properties",
          );
        }
        Object.defineProperty(out, key, {
          configurable: false,
          enumerable: true,
          value: canonicalValue(descriptor.value, depth + 1, ancestors),
          writable: false,
        });
      }
      return out;
    } finally {
      ancestors.delete(value);
    }
  }
  throw new TarballValidationError(`canonical JSON refuses value type ${typeof value}`);
}

export function canonicalJson(value) {
  return `${JSON.stringify(canonicalValue(value))}\n`;
}

function allZero(bytes) {
  for (const byte of bytes) if (byte !== 0) return false;
  return true;
}

function tarString(field, label) {
  const nul = field.indexOf(0);
  const content = nul === -1 ? field : field.subarray(0, nul);
  if (nul !== -1 && !allZero(field.subarray(nul))) {
    throw new TarballValidationError(`${label} has non-zero bytes after its NUL terminator`);
  }
  let value;
  try {
    value = UTF8.decode(content);
  } catch {
    throw new TarballValidationError(`${label} is not strict UTF-8`);
  }
  if (!Buffer.from(value, "utf8").equals(content)) {
    throw new TarballValidationError(`${label} is not canonical UTF-8`);
  }
  return value;
}

function tarOctal(field, label) {
  if ((field[0] & 0x80) !== 0) {
    throw new TarballValidationError(`${label} uses unsupported base-256 encoding`);
  }
  const raw = field.toString("ascii").replace(/[\0 ]+$/u, "").replace(/^ +/u, "");
  if (raw === "") return 0;
  if (!/^[0-7]+$/u.test(raw)) throw new TarballValidationError(`${label} is not canonical octal`);
  const value = Number.parseInt(raw, 8);
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TarballValidationError(`${label} is outside the safe integer range`);
  }
  return value;
}

function headerChecksum(header) {
  let sum = 0;
  for (let index = 0; index < TAR_BLOCK; index++) {
    sum += index >= 148 && index < 156 ? 0x20 : header[index];
  }
  return sum;
}

function validateCanonicalGzipHeader(compressed) {
  if (compressed.length < 18) throw new TarballValidationError("gzip archive is shorter than its canonical header and trailer");
  if (compressed[0] !== 0x1f || compressed[1] !== 0x8b || compressed[2] !== 0x08) {
    throw new TarballValidationError("gzip archive is not the canonical deflate format");
  }
  // FLG must be zero: FEXTRA, FNAME, FCOMMENT and FHCRC are alternate metadata carriers.
  if (compressed[3] !== 0) throw new TarballValidationError("gzip archive carries forbidden optional header metadata");
  if (!compressed.subarray(0, 10).equals(CANONICAL_GZIP_HEADER)) {
    throw new TarballValidationError("gzip archive header is not the canonical npm pack header");
  }
}

function inflateExactlyOneCanonicalGzipMember(compressed, gzipCapabilities = GZIP_CAPABILITIES) {
  validateCanonicalGzipHeader(compressed);

  // Do not parse DEFLATE framing ourselves. Node's bounded raw inflater reports how many bytes it
  // consumed through the *first* DEFLATE end-of-stream. With canonical gzip's fixed ten-byte header,
  // the only permitted remaining bytes are its fixed eight-byte trailer. This rejects a second gzip
  // member (including one carrying FNAME/FCOMMENT) and arbitrary raw suffixes before tar parsing.
  // The raw inflater does not authenticate gzip trailer fields. Node >=22.2 exposes crc32 for an
  // explicit CRC32/ISIZE check; supported earlier Node 20 runtimes instead use bounded gunzip only
  // after this exact-one-member framing check, so concatenation cannot regain acceptance there.
  // This is deliberately bounded by MAX_UNCOMPRESSED_BYTES; it validates one Node-zlib member frame,
  // not a general-purpose recursive gzip container.
  let framed;
  try {
    framed = zlib.inflateRawSync(compressed.subarray(GZIP_HEADER_BYTES), {
      info: true,
      maxOutputLength: MAX_UNCOMPRESSED_BYTES,
    });
  } catch {
    throw new TarballValidationError("cannot inflate canonical gzip member");
  }
  const consumed = Number(framed?.engine?.bytesWritten);
  if (!Number.isSafeInteger(consumed) || consumed < 0) {
    throw new TarballValidationError("canonical gzip member framing is unavailable");
  }
  const memberBytes = GZIP_HEADER_BYTES + consumed + GZIP_TRAILER_BYTES;
  if (memberBytes !== compressed.length) {
    throw new TarballValidationError("gzip archive must contain exactly one canonical member with no trailing bytes");
  }
  const uncompressed = Buffer.from(framed.buffer);
  const trailer = compressed.subarray(memberBytes - GZIP_TRAILER_BYTES);
  const expectedCrc32 = trailer.readUInt32LE(0);
  const expectedSize = trailer.readUInt32LE(4);
  if (typeof gzipCapabilities.crc32 === "function") {
    if ((gzipCapabilities.crc32(uncompressed) >>> 0) !== expectedCrc32 || (uncompressed.length >>> 0) !== expectedSize) {
      throw new TarballValidationError("canonical gzip member trailer CRC32 or size is invalid");
    }
  } else {
    let trailerValidated;
    try {
      trailerValidated = gzipCapabilities.gunzipSync(compressed, { maxOutputLength: MAX_UNCOMPRESSED_BYTES });
    } catch {
      throw new TarballValidationError("canonical gzip member trailer CRC32 or size is invalid");
    }
    if (!Buffer.from(trailerValidated).equals(uncompressed)) {
      throw new TarballValidationError("canonical gzip member trailer CRC32 or size is invalid");
    }
  }
  return uncompressed;
}

function validateArchivePath(path) {
  if (path === "" || path.startsWith("/") || path.includes("\\")) {
    throw new TarballValidationError("unsafe tar entry path");
  }
  if (FORBIDDEN_PATH_CHARS_RE.test(path)) {
    throw new TarballValidationError("tar entry path contains control characters");
  }
  const components = path.split("/");
  if (components.some((component) => component === "" || component === "." || component === "..")) {
    throw new TarballValidationError("tar entry path is not canonical");
  }
  if (components[0] !== "package" || components.length < 2) {
    throw new TarballValidationError("tar entry path escapes package root");
  }
  return components.slice(1).join("/");
}

function parseTar(uncompressed) {
  const entries = [];
  const seen = new Set();
  let offset = 0;
  let terminated = false;

  while (offset + TAR_BLOCK <= uncompressed.length) {
    const header = uncompressed.subarray(offset, offset + TAR_BLOCK);
    if (allZero(header)) {
      const second = uncompressed.subarray(offset + TAR_BLOCK, offset + 2 * TAR_BLOCK);
      if (second.length !== TAR_BLOCK || !allZero(second)) {
        throw new TarballValidationError("tar archive has only one zero terminator block");
      }
      if (!allZero(uncompressed.subarray(offset + 2 * TAR_BLOCK))) {
        throw new TarballValidationError("tar archive has non-zero data after its terminator");
      }
      terminated = true;
      break;
    }

    if (entries.length >= MAX_ENTRIES) {
      throw new TarballValidationError(`tar archive exceeds ${MAX_ENTRIES} entries`);
    }
    const storedChecksum = tarOctal(header.subarray(148, 156), "tar checksum");
    const observedChecksum = headerChecksum(header);
    if (storedChecksum !== observedChecksum) {
      throw new TarballValidationError(
        `tar header checksum mismatch: expected ${storedChecksum}, observed ${observedChecksum}`,
      );
    }
    if (!header.subarray(257, 263).equals(Buffer.from([0x75, 0x73, 0x74, 0x61, 0x72, 0x00]))) {
      throw new TarballValidationError("tar entry is not canonical ustar");
    }
    if (!header.subarray(263, 265).equals(Buffer.from("00", "ascii"))) {
      throw new TarballValidationError("tar entry has an unsupported ustar version");
    }

    const type = header[156];
    if (type !== 0 && type !== 0x30) {
      const printable = type >= 0x20 && type <= 0x7e ? String.fromCharCode(type) : `0x${type.toString(16)}`;
      throw new TarballValidationError(
        `tar entry type ${printable} is forbidden; links, directories, and special entries are not publishable files`,
      );
    }
    const linkName = tarString(header.subarray(157, 257), "tar link name");
    if (linkName !== "") throw new TarballValidationError("regular tar entry carries a link target");
    const uid = tarOctal(header.subarray(108, 116), "tar uid");
    const gid = tarOctal(header.subarray(116, 124), "tar gid");
    if (uid !== 0 || gid !== 0) throw new TarballValidationError("tar entry carries noncanonical ownership metadata");
    if (tarOctal(header.subarray(136, 148), "tar mtime") !== CANONICAL_NPM_TAR_MTIME) {
      throw new TarballValidationError("tar entry carries noncanonical timestamp metadata");
    }
    if (tarString(header.subarray(265, 297), "tar uname") !== "" ||
        tarString(header.subarray(297, 329), "tar gname") !== "") {
      throw new TarballValidationError("tar entry carries noncanonical owner-name metadata");
    }
    if (tarOctal(header.subarray(329, 337), "tar device major") !== 0 ||
        tarOctal(header.subarray(337, 345), "tar device minor") !== 0 ||
        !allZero(header.subarray(500, 512))) {
      throw new TarballValidationError("tar entry carries noncanonical ustar metadata");
    }

    const name = tarString(header.subarray(0, 100), "tar name");
    const prefix = tarString(header.subarray(345, 500), "tar prefix");
    const archivePath = prefix === "" ? name : `${prefix}/${name}`;
    const relativePath = validateArchivePath(archivePath);
    if (seen.has(relativePath)) {
      throw new TarballValidationError("duplicate tar entry path");
    }
    seen.add(relativePath);

    const size = tarOctal(header.subarray(124, 136), "tar entry size");
    if (size > MAX_ENTRY_BYTES) {
      throw new TarballValidationError(`tar entry exceeds ${MAX_ENTRY_BYTES} bytes`);
    }
    const mode = tarOctal(header.subarray(100, 108), "tar entry mode");
    if (mode > 0o777) {
      throw new TarballValidationError("tar entry carries forbidden special permission bits");
    }
    const contentStart = offset + TAR_BLOCK;
    const contentEnd = contentStart + size;
    const paddedEnd = contentStart + Math.ceil(size / TAR_BLOCK) * TAR_BLOCK;
    if (contentEnd > uncompressed.length || paddedEnd > uncompressed.length) {
      throw new TarballValidationError("tar entry is truncated");
    }
    if (!allZero(uncompressed.subarray(contentEnd, paddedEnd))) {
      throw new TarballValidationError("tar entry has non-zero padding");
    }
    const content = Buffer.from(uncompressed.subarray(contentStart, contentEnd));
    entries.push({
      content,
      mode,
      path: relativePath,
      sha256: sha256Hex(content),
      size,
    });
    offset = paddedEnd;
  }

  if (!terminated) throw new TarballValidationError("tar archive has no two-block terminator");
  if (entries.length === 0) throw new TarballValidationError("tar archive contains zero files");
  if (!seen.has("package.json")) throw new TarballValidationError("tar archive has no package.json");
  entries.sort((left, right) => bytewiseCompare(left.path, right.path));
  return entries;
}

function assertRegularSingleLink(stat, where) {
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new TarballValidationError(`tarball must be a real regular file (${where})`);
  }
  if (Number(stat.nlink) !== 1) {
    throw new TarballValidationError(`tarball must have exactly one hard link (${where})`);
  }
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function sameState(left, right) {
  return sameIdentity(left, right)
    && left.size === right.size
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid
    && left.nlink === right.nlink
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function readStableRegularFile(tarballPath) {
  const before = lstatSync(tarballPath, { bigint: true });
  assertRegularSingleLink(before, "path before open");
  if (before.size <= 0n || before.size > BigInt(MAX_COMPRESSED_BYTES)) {
    throw new TarballValidationError(
      `tarball size ${before.size} is outside 1..${MAX_COMPRESSED_BYTES} bytes`,
    );
  }

  if (!Number.isInteger(fsConstants.O_NOFOLLOW)) {
    throw new TarballValidationError("this platform has no O_NOFOLLOW support for stable tarball reads");
  }
  let fd;
  try {
    fd = openSync(tarballPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const opened = fstatSync(fd, { bigint: true });
    assertRegularSingleLink(opened, "opened descriptor");
    if (!sameIdentity(before, opened)) {
      throw new TarballValidationError("tarball path changed during open");
    }
    if (opened.size <= 0n || opened.size > BigInt(MAX_COMPRESSED_BYTES)) {
      throw new TarballValidationError(
        `tarball size ${opened.size} is outside 1..${MAX_COMPRESSED_BYTES} bytes`,
      );
    }

    const compressed = Buffer.alloc(Number(opened.size));
    let offset = 0;
    while (offset < compressed.length) {
      const count = readSync(fd, compressed, offset, compressed.length - offset, offset);
      if (count === 0) {
        throw new TarballValidationError("tarball became shorter during read");
      }
      offset += count;
    }
    const afterDescriptor = fstatSync(fd, { bigint: true });
    assertRegularSingleLink(afterDescriptor, "opened descriptor after read");
    const afterPath = lstatSync(tarballPath, { bigint: true });
    assertRegularSingleLink(afterPath, "path after read");
    if (!sameState(opened, afterDescriptor) || !sameState(before, afterPath)) {
      throw new TarballValidationError("tarball identity or metadata changed during stable read");
    }
    return compressed;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function readSafeNpmTarballBytesWithCapabilities(bytes, gzipCapabilities) {
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) {
    throw new TarballValidationError("tarball bytes must be a Buffer or Uint8Array");
  }
  const compressed = Buffer.from(bytes);
  if (compressed.length <= 0 || compressed.length > MAX_COMPRESSED_BYTES) {
    throw new TarballValidationError(
      `tarball size ${compressed.length} is outside 1..${MAX_COMPRESSED_BYTES} bytes`,
    );
  }
  const uncompressed = inflateExactlyOneCanonicalGzipMember(compressed, gzipCapabilities);
  const entries = parseTar(uncompressed);
  const packlist = entries.map(({ mode, path, sha256, size }) => ({ mode, path, sha256, size }));
  const packlistBytes = Buffer.from(canonicalJson(packlist), "utf8");
  return {
    compressedSize: compressed.length,
    entries,
    packlistCount: packlist.length,
    packlistDigest: sha256Hex(packlistBytes),
    packlistSize: packlist.reduce((sum, entry) => sum + entry.size, 0),
    tarballSha256: sha256Hex(compressed),
    uncompressedSize: uncompressed.length,
  };
}

export function readSafeNpmTarballBytes(bytes) {
  return readSafeNpmTarballBytesWithCapabilities(bytes, GZIP_CAPABILITIES);
}

// A narrowly injected capability seam proves the Node-20 fallback while production always uses the
// runtime namespace. It never permits a caller to skip exact-member framing or tar validation.
export function readSafeNpmTarballBytesForSelftest(bytes, overrides = {}) {
  return readSafeNpmTarballBytesWithCapabilities(bytes, { ...GZIP_CAPABILITIES, ...overrides });
}

export function readSafeNpmTarball(tarballPath) {
  return readSafeNpmTarballBytes(readStableRegularFile(tarballPath));
}
