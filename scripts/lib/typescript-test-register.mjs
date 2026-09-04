/**
 * Register the repository's platform-neutral TypeScript test hooks.
 *
 * The knockout observer runs in a pinned Linux container while a developer may have installed the
 * public toolchain on macOS. `tsx` delegates to a platform-specific esbuild binary, so copying an
 * attested macOS node_modules tree into that Linux namespace makes the clean evidence baseline die
 * before a test loads. The TypeScript compiler itself is JavaScript and is already part of the
 * attested public runtime closure, so these narrow hooks preserve source execution without carrying
 * a host-native executable across the boundary.
 *
 * Node 20 supports asynchronous `module.register`; newer Node 22/24 releases provide the simpler
 * synchronous `module.registerHooks`. The supported runtime matrix needs both paths until Node 20
 * leaves the product contract.
 */
import * as moduleApi from "node:module";
import * as hooks from "./typescript-test-hooks.mjs";

if (typeof moduleApi.registerHooks === "function") {
  moduleApi.registerHooks({ resolve: hooks.resolve, load: hooks.load });
} else {
  moduleApi.register(new URL("./typescript-test-hooks.mjs", import.meta.url), import.meta.url);
}
