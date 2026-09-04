/**
 * Shared post-load runtime-integrity primitives for secret-bearing portable crypto paths.
 *
 * This is deliberately one mechanism, not per-feature copies.  It detects persistent mutations
 * made after module evaluation and provides byte normalization through captured intrinsics.  It is
 * not a claim that arbitrary code already executing in the same realm can be made harmless.
 */

const globalObject = globalThis;
const ReflectObject = Reflect;
const ObjectCtor = Object;
const objectPrototype = ObjectCtor.prototype;
const NumberCtor = Number;
const ArrayCtor = Array;
const reflectApply = ReflectObject.apply;
const reflectOwnKeys = ReflectObject.ownKeys;
const objectGetOwnPropertyDescriptor = ObjectCtor.getOwnPropertyDescriptor;
const objectGetPrototypeOf = ObjectCtor.getPrototypeOf;
const objectIs = ObjectCtor.is;
const numberIsSafeInteger = NumberCtor.isSafeInteger;
const Uint8ArrayCtor = Uint8Array;
const ArrayBufferCtor = ArrayBuffer;
const DataViewCtor = DataView;
const TextEncoderCtor = TextEncoder;
const textEncoderEncode = TextEncoderCtor.prototype.encode;
const sharedTextEncoder = new TextEncoderCtor();
const objectHasOwnProperty = objectPrototype.hasOwnProperty;

const typedArrayPrototype = reflectApply(
  objectGetPrototypeOf,
  ObjectCtor,
  [Uint8ArrayCtor.prototype],
) as object;
const typedArrayLengthDescriptor = reflectApply(
  objectGetOwnPropertyDescriptor,
  ObjectCtor,
  [typedArrayPrototype, "length"],
) as PropertyDescriptor | undefined;
const typedArrayBufferDescriptor = reflectApply(
  objectGetOwnPropertyDescriptor,
  ObjectCtor,
  [typedArrayPrototype, "buffer"],
) as PropertyDescriptor | undefined;
const typedArrayTagDescriptor = reflectApply(
  objectGetOwnPropertyDescriptor,
  ObjectCtor,
  [typedArrayPrototype, Symbol.toStringTag],
) as PropertyDescriptor | undefined;
const arrayBufferByteLengthDescriptor = reflectApply(
  objectGetOwnPropertyDescriptor,
  ObjectCtor,
  [ArrayBufferCtor.prototype, "byteLength"],
) as PropertyDescriptor | undefined;
if (
  typeof typedArrayLengthDescriptor?.get !== "function"
  || typeof typedArrayBufferDescriptor?.get !== "function"
  || typeof typedArrayTagDescriptor?.get !== "function"
  || typeof arrayBufferByteLengthDescriptor?.get !== "function"
) {
  throw new Error("crypto runtime bootstrap failed: typed-array brand intrinsics are unavailable");
}
const typedArrayLengthGetter = typedArrayLengthDescriptor.get;
const typedArrayBufferGetter = typedArrayBufferDescriptor.get;
const typedArrayTagGetter = typedArrayTagDescriptor.get;
const arrayBufferByteLengthGetter = arrayBufferByteLengthDescriptor.get;

const cryptoObject = globalObject.crypto as unknown as {
  getRandomValues?: (array: Uint8Array) => Uint8Array;
};
if (typeof cryptoObject !== "object" || cryptoObject === null) {
  throw new Error("crypto runtime bootstrap failed: crypto was unavailable at module load");
}
const cryptoGetRandomValues = cryptoObject.getRandomValues;
const cryptoPrototype = reflectApply(objectGetPrototypeOf, ObjectCtor, [cryptoObject]) as object;

const arrayIteratorDescriptor = reflectApply(
  objectGetOwnPropertyDescriptor,
  ObjectCtor,
  [ArrayCtor.prototype, Symbol.iterator],
) as PropertyDescriptor | undefined;
if (typeof arrayIteratorDescriptor?.value !== "function") {
  throw new Error("crypto runtime bootstrap failed: Array iterator intrinsic is unavailable");
}
const arrayIterator = reflectApply(arrayIteratorDescriptor.value, [], []) as object;
const arrayIteratorPrototype = reflectApply(
  objectGetPrototypeOf,
  ObjectCtor,
  [arrayIterator],
) as object;

export type RuntimeIntegrityTarget = readonly [label: string, target: object];

type DescriptorSetSnapshot = Readonly<{
  label: string;
  target: object;
  prototype: object | null;
  keys: readonly PropertyKey[];
  descriptors: readonly (PropertyDescriptor | undefined)[];
}>;

function captureDescriptorSet(label: string, target: object): DescriptorSetSnapshot {
  const keys = reflectApply(reflectOwnKeys, ReflectObject, [target]) as PropertyKey[];
  const descriptors: (PropertyDescriptor | undefined)[] = [];
  for (let i = 0; i < keys.length; i++) {
    descriptors[i] = reflectApply(
      objectGetOwnPropertyDescriptor,
      ObjectCtor,
      [target, keys[i] as PropertyKey],
    ) as PropertyDescriptor | undefined;
  }
  const prototype = reflectApply(objectGetPrototypeOf, ObjectCtor, [target]) as object | null;
  return { label, target, prototype, keys, descriptors };
}

export function prototypeChainTargets(label: string, start: object): RuntimeIntegrityTarget[] {
  const targets: RuntimeIntegrityTarget[] = [];
  let current: object | null = start;
  let depth = 0;
  while (current !== null && current !== objectPrototype) {
    targets[depth] = [`${label}[${depth}]`, current];
    current = reflectApply(objectGetPrototypeOf, ObjectCtor, [current]) as object | null;
    depth += 1;
  }
  return targets;
}

const baseTargets: readonly RuntimeIntegrityTarget[] = [
  ["Object", ObjectCtor], ["Object.prototype", objectPrototype],
  ["Reflect", ReflectObject],
  ["Number", NumberCtor], ["Number.prototype", NumberCtor.prototype],
  ["BigInt", BigInt], ["BigInt.prototype", BigInt.prototype],
  ["String", String], ["String.prototype", String.prototype],
  ["Math", Math],
  ["Map", Map], ["Map.prototype", Map.prototype],
  ["Set", Set], ["Set.prototype", Set.prototype],
  ["WeakMap", WeakMap], ["WeakMap.prototype", WeakMap.prototype],
  ["Array", ArrayCtor], ["Array.prototype", ArrayCtor.prototype],
  ...prototypeChainTargets("%ArrayIteratorPrototype%.prototype-chain", arrayIteratorPrototype),
  ["%TypedArray%", reflectApply(objectGetPrototypeOf, ObjectCtor, [Uint8ArrayCtor]) as object],
  ["%TypedArray%.prototype", typedArrayPrototype],
  ["Int8Array", Int8Array], ["Int8Array.prototype", Int8Array.prototype],
  ["Uint8Array", Uint8ArrayCtor], ["Uint8Array.prototype", Uint8ArrayCtor.prototype],
  ["Uint8ClampedArray", Uint8ClampedArray], ["Uint8ClampedArray.prototype", Uint8ClampedArray.prototype],
  ["Int16Array", Int16Array], ["Int16Array.prototype", Int16Array.prototype],
  ["Uint16Array", Uint16Array], ["Uint16Array.prototype", Uint16Array.prototype],
  ["Int32Array", Int32Array], ["Int32Array.prototype", Int32Array.prototype],
  ["Uint32Array", Uint32Array], ["Uint32Array.prototype", Uint32Array.prototype],
  ["BigInt64Array", BigInt64Array], ["BigInt64Array.prototype", BigInt64Array.prototype],
  ["BigUint64Array", BigUint64Array], ["BigUint64Array.prototype", BigUint64Array.prototype],
  ["Float32Array", Float32Array], ["Float32Array.prototype", Float32Array.prototype],
  ["Float64Array", Float64Array], ["Float64Array.prototype", Float64Array.prototype],
  ["DataView", DataView], ["DataView.prototype", DataView.prototype],
  ["ArrayBuffer", ArrayBufferCtor], ["ArrayBuffer.prototype", ArrayBufferCtor.prototype],
  ["crypto", cryptoObject], ["Crypto.prototype", cryptoPrototype],
];

const baseSnapshots: DescriptorSetSnapshot[] = [];
for (let i = 0; i < baseTargets.length; i++) {
  const target = baseTargets[i] as RuntimeIntegrityTarget;
  baseSnapshots[i] = captureDescriptorSet(target[0], target[1]);
}

const globalBindingNames = [
  "globalThis", "Object", "Reflect", "Number", "BigInt", "String", "Math", "Map", "Set",
  "WeakMap", "Array", "Int8Array", "Uint8Array", "Uint8ClampedArray", "Int16Array",
  "Uint16Array", "Int32Array", "Uint32Array", "BigInt64Array", "BigUint64Array",
  "Float32Array", "Float64Array", "DataView", "ArrayBuffer", "crypto",
] as const;
const globalBindingDescriptors: (PropertyDescriptor | undefined)[] = [];
for (let i = 0; i < globalBindingNames.length; i++) {
  globalBindingDescriptors[i] = reflectApply(
    objectGetOwnPropertyDescriptor,
    ObjectCtor,
    [globalObject, globalBindingNames[i]],
  ) as PropertyDescriptor | undefined;
}

const ABSENT_DESCRIPTOR_FIELD = ObjectCtor.freeze({});
const descriptorFields = ["configurable", "enumerable", "value", "writable", "get", "set"] as const;

function descriptorOwnField(descriptor: PropertyDescriptor, key: PropertyKey): unknown {
  const fieldDescriptor = reflectApply(
    objectGetOwnPropertyDescriptor,
    ObjectCtor,
    [descriptor, key],
  ) as PropertyDescriptor | undefined;
  return fieldDescriptor === undefined ? ABSENT_DESCRIPTOR_FIELD : fieldDescriptor.value;
}

function sameDescriptor(left: PropertyDescriptor | undefined, right: PropertyDescriptor | undefined): boolean {
  if (left === undefined || right === undefined) return left === right;
  for (let i = 0; i < descriptorFields.length; i++) {
    const field = descriptorFields[i] as typeof descriptorFields[number];
    if (!(reflectApply(objectIs, ObjectCtor, [
      descriptorOwnField(left, field),
      descriptorOwnField(right, field),
    ]) as boolean)) return false;
  }
  return true;
}

function descriptorSetIsCurrent(snapshot: DescriptorSetSnapshot): boolean {
  if (reflectApply(objectGetPrototypeOf, ObjectCtor, [snapshot.target]) !== snapshot.prototype) return false;
  const currentKeys = reflectApply(reflectOwnKeys, ReflectObject, [snapshot.target]) as PropertyKey[];
  if (currentKeys.length !== snapshot.keys.length) return false;
  for (let i = 0; i < currentKeys.length; i++) {
    if (currentKeys[i] !== snapshot.keys[i]) return false;
    const current = reflectApply(
      objectGetOwnPropertyDescriptor,
      ObjectCtor,
      [snapshot.target, currentKeys[i] as PropertyKey],
    ) as PropertyDescriptor | undefined;
    if (!sameDescriptor(current, snapshot.descriptors[i])) return false;
  }
  return true;
}

/** Build an operation-specific fence on top of the one shared primordial baseline. */
export function createCryptoRuntimeIntegrityFence(
  operation: string,
  additionalTargets: readonly RuntimeIntegrityTarget[],
): () => void {
  const additionalSnapshots: DescriptorSetSnapshot[] = [];
  for (let i = 0; i < additionalTargets.length; i++) {
    const target = additionalTargets[i] as RuntimeIntegrityTarget;
    additionalSnapshots[i] = captureDescriptorSet(target[0], target[1]);
  }

  return function assertCryptoRuntimeIntegrity(): void {
    for (let i = 0; i < baseSnapshots.length; i++) {
      const snapshot = baseSnapshots[i] as DescriptorSetSnapshot;
      if (!descriptorSetIsCurrent(snapshot)) {
        throw new Error(`${operation} runtime intrinsic integrity check failed: ${snapshot.label}`);
      }
    }
    for (let i = 0; i < additionalSnapshots.length; i++) {
      const snapshot = additionalSnapshots[i] as DescriptorSetSnapshot;
      if (!descriptorSetIsCurrent(snapshot)) {
        throw new Error(`${operation} runtime intrinsic integrity check failed: ${snapshot.label}`);
      }
    }
    for (let i = 0; i < globalBindingNames.length; i++) {
      const current = reflectApply(
        objectGetOwnPropertyDescriptor,
        ObjectCtor,
        [globalObject, globalBindingNames[i]],
      ) as PropertyDescriptor | undefined;
      if (!sameDescriptor(current, globalBindingDescriptors[i])) {
        throw new Error(`${operation} runtime intrinsic integrity check failed: globalThis.${globalBindingNames[i]}`);
      }
    }
  };
}

/** Invoke a captured callable without consulting live Function.prototype.call/apply slots. */
export function invokeCaptured(
  callable: (...args: never[]) => unknown,
  receiver: unknown,
  args: readonly unknown[],
): unknown {
  return reflectApply(callable, receiver, args);
}

/** Encode UTF-8 through the one module-load-captured TextEncoder mechanism. */
export function capturedTextEncode(value: string): Uint8Array {
  return reflectApply(textEncoderEncode, sharedTextEncoder, [value]) as Uint8Array;
}

function propertyKeyLabel(key: PropertyKey): string {
  return typeof key === "string" ? key : "<symbol>";
}

/**
 * Read only an own data property without invoking an accessor. A Proxy descriptor trap can still
 * execute; secret-bearing callers therefore normalize first and run their final integrity fence
 * after all such reads.
 */
export function ownDataValue(
  target: unknown,
  key: PropertyKey,
  label: string,
  required: boolean,
): unknown {
  if (typeof target !== "object" || target === null) throw new Error(`${label}: expected an object`);
  const descriptor = reflectApply(
    objectGetOwnPropertyDescriptor,
    ObjectCtor,
    [target, key],
  ) as PropertyDescriptor | undefined;
  if (descriptor === undefined) {
    if (required) throw new Error(`${label}: missing own data property ${propertyKeyLabel(key)}`);
    return undefined;
  }
  if (!(reflectApply(objectHasOwnProperty, descriptor, ["value"]) as boolean)) {
    throw new Error(`${label}: ${propertyKeyLabel(key)} must be an own data property`);
  }
  return descriptor.value;
}

/** Cross-realm Uint8Array/Buffer length through the captured typed-array brand getter. */
export function cryptoByteLength(value: Uint8Array): number {
  return reflectApply(typedArrayLengthGetter, value, []) as number;
}

/**
 * Copy a branded Uint8Array (including Buffer/cross-realm values) without caller dispatch and
 * reject proxies, non-byte typed arrays, detached buffers, and SharedArrayBuffer-backed views.
 */
export function copyUnsharedUint8Array(value: unknown, label: string): Uint8Array {
  if (typeof value !== "object" || value === null) throw new Error(`${label}: expected a Uint8Array`);
  let sourceLength: number;
  let sourceBuffer: object;
  let sourceTag: unknown;
  try {
    sourceLength = reflectApply(typedArrayLengthGetter, value, []) as number;
    sourceBuffer = reflectApply(typedArrayBufferGetter, value, []) as object;
    sourceTag = reflectApply(typedArrayTagGetter, value, []);
  } catch {
    throw new Error(`${label}: expected a Uint8Array`);
  }
  if (sourceTag !== "Uint8Array") throw new Error(`${label}: expected a Uint8Array`);
  try {
    reflectApply(arrayBufferByteLengthGetter, sourceBuffer, []);
    // The byteLength getter distinguishes SharedArrayBuffer but reports zero for a detached
    // ArrayBuffer. Constructing a zero-length native DataView is the captured, cross-realm
    // attachment check: unlike ArrayBuffer.prototype.slice it performs no caller-controlled
    // constructor/@@species lookup, succeeds for a legitimate empty buffer, and throws if detached.
    new DataViewCtor(sourceBuffer as ArrayBuffer, 0, 0);
  } catch {
    throw new Error(
      `${label}: expected a Uint8Array backed by a non-shared ArrayBuffer that is still attached`,
    );
  }
  const source = value as Uint8Array;
  const out = new Uint8ArrayCtor(sourceLength);
  for (let i = 0; i < sourceLength; i++) out[i] = source[i] as number;
  return out;
}

/** Zero a normalized, non-shared byte array without live prototype dispatch. */
export function zeroCryptoBytes(value: Uint8Array): void {
  const length = cryptoByteLength(value);
  for (let i = 0; i < length; i++) value[i] = 0;
}

/** Keep every operation on a private byte copy inside one cleanup scope, including throw paths. */
export function withZeroedCryptoBytes<T>(value: Uint8Array, operation: (bytes: Uint8Array) => T): T {
  try {
    return operation(value);
  } finally {
    zeroCryptoBytes(value);
  }
}

/** Draw from the module-load captured native CSPRNG. Callers still run their operation fence. */
export function capturedCryptoRandomBytes(length: number, label: string): Uint8Array {
  if (!(reflectApply(numberIsSafeInteger, NumberCtor, [length]) as boolean) || length < 0 || length > 65_536) {
    throw new Error(`${label}: length must be a safe integer between 0 and 65536`);
  }
  if (typeof cryptoGetRandomValues !== "function") {
    throw new Error(`${label}: crypto.getRandomValues was unavailable at module load`);
  }
  const out = new Uint8ArrayCtor(length);
  reflectApply(cryptoGetRandomValues, cryptoObject, [out]);
  return out;
}
