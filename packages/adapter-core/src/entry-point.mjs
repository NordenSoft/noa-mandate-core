/**
 * entry-point.mjs — "was THIS module the one Node was asked to run?"
 *
 * The usual check, `import.meta.url === \`file://${process.argv[1]}\``, compares a RESOLVED module URL
 * with the path the user typed. npm installs every `bin` as a SYMLINK (`node_modules/.bin/noa-approve`
 * -> `../noa-mcp-adapter-core/src/approve-cli.mjs`), so for exactly the way a published CLI is meant
 * to be run the two never match: the module loads, the body is skipped, and the process exits 0
 * having done nothing. A CLI that silently does nothing and reports success is worse than one that
 * fails: an approval the operator believes was recorded never was.
 *
 * Both sides are therefore reduced to their real filesystem paths before comparing. Any failure to
 * resolve (no argv[1], a path that no longer exists) answers `false`: the body does not run, which
 * is the conservative outcome for a module that is also imported as a library.
 */
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

/**
 * @param {string} importMetaUrl  the caller's own `import.meta.url`
 * @param {string | undefined} [argv1]  the script path Node was started with (default `process.argv[1]`)
 * @returns {boolean}
 */
export function isEntryPoint(importMetaUrl, argv1 = process.argv[1]) {
  if (typeof importMetaUrl !== "string" || typeof argv1 !== "string" || argv1.length === 0) return false;
  try {
    // A HARD link has its own real path, so a launch through one answers false (body skipped); npm never creates one.
    return realpathSync(fileURLToPath(importMetaUrl)) === realpathSync(argv1);
  } catch {
    return false;
  }
}
