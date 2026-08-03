export type ExactRecord = Record<string, unknown>;
export type CaptureContext = WeakSet<object>;
export type CaptureFailure = (message: string) => never;

function reflect<T>(read: () => T, label: string, fail: CaptureFailure): T {
  try {
    return read();
  } catch {
    return fail(`${label} is invalid`);
  }
}

export function captureRecord(
  value: unknown,
  label: string,
  context: CaptureContext,
  fail: CaptureFailure,
): ExactRecord {
  if (!value || typeof value !== "object" || reflect(() => Array.isArray(value), label, fail)) {
    return fail(`${label} must be a plain object`);
  }
  if (context.has(value)) return fail(`${label} aliases another record`);
  context.add(value);

  const prototype = reflect(() => Reflect.getPrototypeOf(value), label, fail);
  const descriptors = reflect(() => Object.getOwnPropertyDescriptors(value), label, fail);
  if (prototype !== Object.prototype && prototype !== null) {
    return fail(`${label} must be a plain object`);
  }

  const captured: ExactRecord = Object.create(null) as ExactRecord;
  for (const key of Reflect.ownKeys(descriptors)) {
    if (typeof key !== "string") return fail(`${label} contains a symbol field`);
    const descriptor = descriptors[key];
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      return fail(`${label} contains a non-data or non-enumerable field`);
    }
    captured[key] = descriptor.value;
  }
  return captured;
}

export function exactCapturedRecord(
  captured: ExactRecord,
  keys: readonly string[],
  label: string,
  fail: CaptureFailure,
): ExactRecord {
  const actualKeys = Object.keys(captured);
  if (actualKeys.length !== keys.length || actualKeys.some((key) => !keys.includes(key))) {
    return fail(`${label} contains missing or unknown fields`);
  }
  return captured;
}

export function exactRecord(
  value: unknown,
  keys: readonly string[],
  label: string,
  context: CaptureContext,
  fail: CaptureFailure,
): ExactRecord {
  return exactCapturedRecord(captureRecord(value, label, context, fail), keys, label, fail);
}

export function captureDenseArray(
  value: unknown,
  label: string,
  context: CaptureContext,
  fail: CaptureFailure,
): readonly unknown[] {
  if (!value || typeof value !== "object" || !reflect(() => Array.isArray(value), label, fail)) {
    return fail(`${label} must be an array`);
  }
  if (context.has(value)) return fail(`${label} aliases another record`);
  context.add(value);
  const prototype = reflect(() => Reflect.getPrototypeOf(value), label, fail);
  const descriptors = reflect(
    () =>
      Object.getOwnPropertyDescriptors(value) as unknown as Record<
        PropertyKey,
        PropertyDescriptor | undefined
      >,
    label,
    fail,
  );
  if (prototype !== Array.prototype) {
    return fail(`${label} must be an ordinary array`);
  }

  const lengthDescriptor = descriptors.length;
  if (!lengthDescriptor || !("value" in lengthDescriptor)) {
    return fail(`${label} has an invalid length`);
  }
  const length = lengthDescriptor.value;
  if (typeof length !== "number" || !Number.isSafeInteger(length) || length < 0) {
    return fail(`${label} has an invalid length`);
  }

  const keys = Reflect.ownKeys(descriptors);
  if (keys.length !== length + 1 || keys.some((key) => typeof key !== "string")) {
    return fail(`${label} must be dense and contain no extra fields`);
  }
  const captured: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      return fail(`${label} must contain enumerable data elements`);
    }
    captured.push(descriptor.value);
  }
  return Object.freeze(captured);
}
