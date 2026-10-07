/**
 * Owns: the generated fixtures that pin the relay's Rust grant approval
 * (`relay/crates/oaath-relay/src/grant/`) to the SDK's own Kernel v4
 * permission packaging, all-chain approval, and root-key signatures.
 *
 * Every expected value comes from the SDK sources: `sessionOperator` packages
 * over `deriveSessionPolicyProfiles`, `kernelPermissionInstallNonce`,
 * `kernelV4ReplayableInstallDigest`, `approveKernelPermissionAllChain` signed by
 * `ecdsaKey` / `p256Key` / `webauthnKey` (each self-verifies its signature), and
 * `kernelAllChainCapabilityHash`. Keys are fixed; a WebAuthn authenticator is
 * emulated from a fixed P-256 key. No chain, clock, or network is touched.
 *
 * Run: bun run fixtures:protocol (which runs this after the protocol fixtures)
 *
 * @author taek <leekt216@gmail.com>
 */
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const sdk = (path) => import(`${root}packages/sdk/src/${path}`);
const P = await import(`${root}packages/protocol/src/index.ts`);
const { kernelV4Deployment, kernelV4ReplayableInstallDigest, kernelV4ReplayableInstallTypedData } =
  await sdk("kernel-v4.ts");
const { credentialKey } = await sdk("kernel/key/credential.ts");
const { ecdsaKey } = await sdk("kernel/key/ecdsa.ts");
const { p256Key } = await sdk("kernel/key/p256.ts");
const { webauthnKey } = await sdk("kernel/key/webauthn.ts");
const { sessionOperator } = await sdk("kernel/operator/session.ts");
const { deriveSessionPolicyProfiles } = await sdk("kernel/permission/profiles.ts");
const { kernelPermissionInstallNonce } = await sdk("kernel/permission/install-nonce.ts");
const { approveKernelPermissionAllChain, kernelAllChainCapabilityHash } = await sdk(
  "kernel/permission/materialize.ts",
);
const { privateKeyToAccount } = await import(
  `${root}packages/sdk/node_modules/viem/_esm/accounts/privateKeyToAccount.js`
);
const { p256 } = await import(`${root}packages/protocol/node_modules/@noble/curves/nist.js`);
const { sha256 } = await import(`${root}packages/protocol/node_modules/@noble/hashes/sha2.js`);
const { keccak_256 } = await import(`${root}packages/protocol/node_modules/@noble/hashes/sha3.js`);

const OUTPUT = `${root}relay/fixtures/grant`;
const RP_ID = "oaath.test";
const ORIGIN = "https://oaath.test";

const hex = (bytes) => `0x${Buffer.from(bytes).toString("hex")}`;
const bytes = (value) => Uint8Array.from(Buffer.from(value.slice(2), "hex"));
const base64Url = (value) => Buffer.from(value).toString("base64url");
const fixedKey = (byte) => bytes(`0x${byte.repeat(32)}`);

// ------------------------------------------------------------------- keys

const ecdsaAccount = privateKeyToAccount(`0x${"11".repeat(32)}`);
const ecdsaOwner = {
  credential: {
    version: "oaath.owner-credential-profile/v1",
    kind: "ecdsa",
    address: ecdsaAccount.address.toLowerCase(),
  },
  key: () =>
    ecdsaKey({
      account: { address: ecdsaAccount.address, sign: ({ hash }) => ecdsaAccount.sign({ hash }) },
      validator: "0x845adb2c711129d4f3966735ed98a9f09fc4ce57",
    }),
};

const p256Secret = fixedKey("22");
const p256Owner = {
  credential: {
    version: "oaath.owner-credential-profile/v1",
    kind: "p256",
    publicKey: hex(p256.getPublicKey(p256Secret, false)),
  },
  key: () =>
    p256Key({
      credential: p256Owner.credential,
      sign: async ({ hash }) =>
        `0x${p256.sign(bytes(hash), p256Secret, { prehash: false, lowS: true }).toCompactHex()}`,
    }),
};

/** A software authenticator: the assertion a platform authenticator returns. */
function authenticator(secret) {
  return async ({ challenge, rpId, origin }) => {
    const authenticatorData = new Uint8Array([
      ...sha256(new TextEncoder().encode(rpId)),
      0x05,
      0,
      0,
      0,
      1,
    ]);
    const clientDataJSON = JSON.stringify({
      type: "webauthn.get",
      challenge,
      origin,
      crossOrigin: false,
    });
    const message = sha256(
      new Uint8Array([...authenticatorData, ...sha256(new TextEncoder().encode(clientDataJSON))]),
    );
    const signature = p256.sign(message, secret, { prehash: false, lowS: true }).toCompactHex();
    return {
      authenticatorData: hex(authenticatorData),
      clientDataJSON,
      responseTypeLocation: "1",
      r: `0x${signature.slice(0, 64)}`,
      s: `0x${signature.slice(64)}`,
    };
  };
}

function webauthnCredential(secret, credentialId, version) {
  return {
    version,
    kind: "webauthn",
    publicKey: hex(p256.getPublicKey(secret, false)),
    authenticatorIdHash: hex(keccak_256(credentialId)),
  };
}

const webauthnSecret = fixedKey("33");
const webauthnCredentialId = new TextEncoder().encode("oaath-fixture-credential");
const webauthnOwner = {
  credential: webauthnCredential(
    webauthnSecret,
    webauthnCredentialId,
    "oaath.owner-credential-profile/v1",
  ),
  key: () =>
    webauthnKey({
      credential: webauthnOwner.credential,
      credentialId: base64Url(webauthnCredentialId),
      rpId: RP_ID,
      origin: ORIGIN,
      authenticate: authenticator(webauthnSecret),
    }),
};

const OPERATORS = {
  ecdsa: {
    version: "oaath.operator-credential-profile/v1",
    kind: "ecdsa",
    address: privateKeyToAccount(`0x${"44".repeat(32)}`).address.toLowerCase(),
  },
  webauthn: webauthnCredential(
    fixedKey("55"),
    new TextEncoder().encode("oaath-fixture-operator"),
    "oaath.operator-credential-profile/v1",
  ),
};

// --------------------------------------------------------------- requests

const POLICY = {
  version: "oaath.grant-policy/v1",
  calls: [
    {
      target: `0x${"aa".repeat(20)}`,
      selector: "0xa9059cbb",
      valueLimit: "0",
      argumentEquals: [],
    },
    {
      target: `0x${"bb".repeat(20)}`,
      selector: "0x12345678",
      valueLimit: "1000",
      argumentEquals: [],
    },
  ],
  validAfter: 100,
  validUntil: 190,
  perChainOperationLimit: { count: 10, intervalSeconds: null },
};

function request(owner, operator, policy = POLICY) {
  return {
    version: "oaath.permission-request/v1",
    requestId: "grant-fixture-1",
    context: {
      version: "oaath.workspace-account-context/v1",
      workspaceId: "account-1",
      workspaceKind: "personal",
      accountId: "account-1",
    },
    application: {
      applicationId: "client-1",
      clientId: "client-1",
      origin: "https://app.example",
      deviceId: "device-1",
    },
    chainScope: "all",
    logicalAccount: {
      version: "oaath.kernel-account-profile/v1",
      kind: "kernel",
      accountIndex: "0",
      kernelVersion: "0.4.0",
      factoryRoute: "kernel_factory",
      entryPoint: { version: "0.9" },
      ownerCredential: owner.credential,
    },
    operatorCredential: operator,
    policy,
    requestedAt: 100,
    expiresAt: 200,
    sessionSigner: null,
  };
}

const ACCOUNT = `0x${"cd".repeat(20)}`;

/** The SDK's own all-chain grant for one request, exactly as prepare/sign build it. */
async function grant(owner, operatorKind, policy = POLICY) {
  const value = request(owner, OPERATORS[operatorKind], policy);
  const parsed = P.parsePermissionRequest(value);
  const requestHash = P.hashPermissionRequest(parsed);
  const installNonce = kernelPermissionInstallNonce(requestHash);
  const packages = sessionOperator({
    key: credentialKey({ credential: parsed.operatorCredential, validator: null }),
    policies: deriveSessionPolicyProfiles(parsed.policy),
  }).resolvePackages(kernelV4Deployment(1));
  const scope = { account: ACCOUNT, nonce: installNonce, packages };
  const signingRequest = P.parseKernelReplayableInstallOwnerSigningRequest({
    version: P.OAATH_OWNER_SIGNING_REQUEST_VERSION,
    kind: "eip712",
    purpose: "kernel-enable",
    signer: { account: ACCOUNT, ownerCredential: owner.credential },
    typedData: kernelV4ReplayableInstallTypedData(scope),
    expectedDigest: kernelV4ReplayableInstallDigest(scope),
    replay: { nonce: installNonce, deadline: null },
  });
  const installApproval = await approveKernelPermissionAllChain({
    owner: owner.key(),
    account: ACCOUNT,
    installNonce,
    packages,
  });
  const capabilityHash = kernelAllChainCapabilityHash(installApproval);
  const artifact = JSON.stringify({
    version: P.OAATH_PERMISSION_DECISION_VERSION,
    kind: "approve",
    requestId: parsed.requestId,
    requestHash,
    decidedAt: parsed.requestedAt,
    approvedPolicy: parsed.policy,
    capabilityHash,
    installApproval,
  });
  return {
    input: { request: value, account: ACCOUNT, rpId: RP_ID, origin: ORIGIN },
    expect: {
      ok: {
        installNonce,
        packages,
        signingRequest,
        digest: installApproval.digest,
        capabilityHash,
        artifact,
      },
    },
  };
}

/** The SDK's refusal code for a policy no Kernel profile can enforce. */
async function refused(owner, policy) {
  try {
    await grant(owner, "ecdsa", policy);
  } catch (error) {
    return {
      input: { request: request(owner, OPERATORS.ecdsa, policy), account: ACCOUNT },
      expect: { error: error.code },
    };
  }
  throw new Error("expected the SDK to refuse the policy");
}

const grants = [];
for (const [ownerName, owner] of Object.entries({
  ecdsa: ecdsaOwner,
  p256: p256Owner,
  webauthn: webauthnOwner,
})) {
  for (const operatorKind of ["ecdsa", "webauthn"]) {
    grants.push({
      name: `${ownerName} root, ${operatorKind} signer`,
      ...(await grant(owner, operatorKind)),
    });
  }
}
grants.push({
  name: "rate-limited policy",
  ...(await grant(ecdsaOwner, "ecdsa", {
    ...POLICY,
    perChainOperationLimit: { count: 3, intervalSeconds: 3600 },
  })),
});
grants.push({
  name: "argument constraint",
  ...(await refused(ecdsaOwner, {
    ...POLICY,
    calls: [{ ...POLICY.calls[0], argumentEquals: [{ index: 0, value: `0x${"00".repeat(32)}` }] }],
  })),
});

// -------------------------------------------------------------- signatures

const DIGEST = `0x${"7e".repeat(32)}`;

async function signature(name, owner, sign, ok, overrides = {}) {
  return {
    name,
    input: {
      ownerCredential: owner.credential,
      digest: DIGEST,
      signature: await sign(),
      rpId: RP_ID,
      origin: ORIGIN,
      ...overrides,
    },
    expect: { ok },
  };
}

const otherEcdsa = privateKeyToAccount(`0x${"66".repeat(32)}`);
const flip = (value) => `${value.slice(0, -2)}${value.endsWith("00") ? "01" : "00"}`;
const n = p256.CURVE.n;
const signatures = [
  await signature("ecdsa raw", ecdsaOwner, () => ecdsaOwner.key().sign(DIGEST), true),
  await signature(
    "ecdsa eip-191",
    ecdsaOwner,
    () => ecdsaAccount.signMessage({ message: { raw: DIGEST } }),
    true,
  ),
  await signature("ecdsa other key", ecdsaOwner, () => otherEcdsa.sign({ hash: DIGEST }), false),
  await signature(
    "ecdsa other digest",
    ecdsaOwner,
    () => ecdsaAccount.sign({ hash: `0x${"7f".repeat(32)}` }),
    false,
  ),
  await signature("p256", p256Owner, () => p256Owner.key().sign(DIGEST), true),
  await signature(
    "p256 high s",
    p256Owner,
    async () => {
      const compact = await p256Owner.key().sign(DIGEST);
      const s = n - BigInt(`0x${compact.slice(66)}`);
      return `${compact.slice(0, 66)}${s.toString(16).padStart(64, "0")}`;
    },
    false,
  ),
  await signature(
    "p256 tampered",
    p256Owner,
    async () => flip(await p256Owner.key().sign(DIGEST)),
    false,
  ),
  await signature("webauthn", webauthnOwner, () => webauthnOwner.key().sign(DIGEST), true),
  await signature(
    "webauthn other origin",
    webauthnOwner,
    () => webauthnOwner.key().sign(DIGEST),
    false,
    { origin: "https://attacker.example" },
  ),
  await signature(
    "webauthn other rp",
    webauthnOwner,
    () => webauthnOwner.key().sign(DIGEST),
    false,
    { rpId: "attacker.example" },
  ),
  await signature(
    "webauthn other digest",
    webauthnOwner,
    () => webauthnOwner.key().sign(`0x${"7f".repeat(32)}`),
    false,
  ),
];

rmSync(OUTPUT, { recursive: true, force: true });
mkdirSync(OUTPUT, { recursive: true });
writeFileSync(`${OUTPUT}/kernelGrantApproval.json`, `${JSON.stringify(grants, null, 2)}\n`);
writeFileSync(`${OUTPUT}/kernelEnableSignature.json`, `${JSON.stringify(signatures, null, 2)}\n`);
console.log(`relay grant fixtures: ${grants.length + signatures.length} cases`);
