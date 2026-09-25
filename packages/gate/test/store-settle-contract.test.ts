/**
 * The settleHold store contract (test/store-settle-contract.ts) over this repository's stores: the
 * in-memory store (one connection), and two detached views of one in-memory state, which behave like
 * two connections to one database.
 */
import { InMemoryStore } from "../src/store.js";
import { DetachedStore } from "./store-cas-contract.js";
import { runSettleHoldStoreContract } from "./store-settle-contract.js";

runSettleHoldStoreContract("in-memory", () => {
  const store = new InMemoryStore();
  return { store, peer: store };
});

runSettleHoldStoreContract("detached", () => {
  const inner = new InMemoryStore();
  return { store: new DetachedStore(inner), peer: new DetachedStore(inner) };
});
