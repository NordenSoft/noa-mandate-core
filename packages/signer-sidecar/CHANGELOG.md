# Changelog — `noa-signer-sidecar`

The root `CHANGELOG.md` scopes itself to `noa-receipt` in its first line, so changes to this package
are recorded here. This file is not part of the published tarball (`files` in `package.json` does
not list it); it is the changelog entry the release controller `.github/workflows/release-npm-mcp.yml`
requires before it stages a version.

## [0.1.0] - 2026-10-06

> **Repository state, not a registry claim.** A version heading here records what the tree contains,
> never what the registry serves. Check `npm view noa-signer-sidecar version` for the published
> version.

### Added

- The first version of this package released from this repository: the process-isolated Ed25519
  signing oracle (`src/sidecar.mjs`, bin `noa-signer-sidecar`) and its client
  (`src/client.mjs`, `createRemoteSigner`), as described in `README.md`. `noa-mcp-proxy` names this
  package as an optional dependency (`^0.1.0`) and loads it only for `--signer-socket`.
- Its dependencies on `noa-mcp-adapter-core` and `noa-receipt` are local links in the repository;
  the release staging rewrites each one to a caret range of the linked package's version, so this
  version can be staged only after those versions are on the registry.

### Registry history

- The registry also holds `0.0.0-stage` and `0.0.1` under this name. Their registry metadata
  describes them as placeholders with no code (two files each), and neither was released through
  the release controller. They stay on the registry; once `0.1.0` is public the maintainer
  deprecates both with `npm deprecate`. `^0.1.0` matches neither of them.
