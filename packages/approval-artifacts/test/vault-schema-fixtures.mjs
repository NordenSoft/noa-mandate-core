// Test-only schema composition. Runtime admission is deliberately outside this fixture module.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { evalSchema } from '../dist/src/schema-eval.js';
import { validateReceiptShape } from '../../../dist/src/schema.js';

export const schemaDir = new URL('../schema/', import.meta.url);
const cache = new Map();
export function schemaFor(name) {
  if (cache.has(name)) return cache.get(name);
  const url = name === 'noa-receipt-0.1'
    ? new URL('../../../schema/noa-receipt-0.1.schema.json', import.meta.url)
    : new URL(`${name}.schema.json`, schemaDir);
  const raw = JSON.parse(readFileSync(url, 'utf8'));
  function expand(node, root) {
    if (Array.isArray(node)) return node.map(x => expand(x, root));
    if (!node || typeof node !== 'object') return node;
    if (node.$ref) {
      const [file, fragment] = node.$ref.split('#');
      const target = file ? schemaFor(file.replace('.schema.json', '')) : root;
      const selected = fragment ? fragment.slice(1).split('/').reduce((v, k) => v[k], target) : target;
      if (!selected) throw new Error(`Unresolved schema reference: ${node.$ref}`);
      return expand(selected, file ? target : root);
    }
    return Object.fromEntries(Object.entries(node).map(([k, v]) => [k, expand(v, root)]));
  }
  const schema = expand(raw, raw);
  cache.set(name, schema);
  return schema;
}
export function schemaCheck(artifact) {
  const name = artifact.spec.replace('noa.', 'noa-').replace('/', '-');
  // The artifact prefix has a dot; names within it retain hyphens.
  const schema = schemaFor(name);
  const result = evalSchema(schema, artifact);
  const receipts = artifact.spec === 'noa.vault-authority-bundle/0.1'
    ? [artifact.deferredReceipt, artifact.approvalReceipt] : [];
  for (const receipt of receipts) {
    const checked = validateReceiptShape(JSON.stringify(receipt));
    if (!checked.ok) result.errors.push(...checked.errors);
  }
  return { ok: result.errors.length === 0, errors: result.errors };
}
export const corpusDir = fileURLToPath(new URL('../conformance/vault-verification/', import.meta.url));
