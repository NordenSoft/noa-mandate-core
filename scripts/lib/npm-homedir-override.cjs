"use strict";

// npm 10 asks node:os for a homedir before it loads npm_config_userconfig. The staging container
// deliberately has no HOME and runs as the host UID, which is not present in the image passwd file.
// Supply that one API with a fixed task-local directory; this is not an environment rebinding and
// npm's cache and configuration remain governed by their explicit npm_config_* paths.
const { mkdirSync } = require("node:fs");
const os = require("node:os");

const TASK_NPM_HOMEDIR = "/noa-tmp/npm-home";
if (process.env.NOA_NPM_HOMEDIR !== TASK_NPM_HOMEDIR) {
  throw new Error("NOA_NPM_HOMEDIR is not the closed staging path");
}
mkdirSync(TASK_NPM_HOMEDIR, { recursive: true, mode: 0o700 });
os.homedir = () => TASK_NPM_HOMEDIR;
