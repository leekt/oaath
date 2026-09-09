import { readFileSync } from "node:fs";
import { p256 } from "@noble/curves/nist.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import {
  hashKernelV4RevocationSigningRequest,
  hashPermissionRequest,
  type KernelV4RevocationSigningRequest,
  parseKernelV4RevocationSigningRequest,
  serializeOwnerSigningArtifact,
} from "@oaath/protocol";
import { vi } from "vitest";
import {
  createMemoryServiceDirectoryStore,
  createServiceDirectory,
  type RelayStore,
} from "../src/index.js";
import { createRelayHandler } from "../src/relay/handler.js";
import {
  approve,
  CALLERS,
  CLIENT_TOKEN,
  createRequest,
  createTestAuthentication,
  createTestClock,
  createTestKms,
  type Harness,
} from "./support.js";

const source = JSON.parse(
  readFileSync(
    new URL("../../protocol/test/fixtures/kernel-revocation-operation.json", import.meta.url),
    "utf8",
  ),
);

// This fixture proves service custody/admission only. The packed consumer proves
// SDK preparation against an actual retained phone-approved Kernel capability.
export async function setupRevocation(store: RelayStore) {
  const key = p256.utils.randomPrivateKey();
  const ownerCredential = {
    ...source.permissionRequest.logicalAccount.ownerCredential,
    publicKey: `0x${bytesToHex(p256.getPublicKey(key, false))}`,
  };
  const { requestId: _id, ...scope } = structuredClone(source.permissionRequest);
  scope.logicalAccount.ownerCredential = ownerCredential;
  const directory = createServiceDirectory(createMemoryServiceDirectoryStore());
  await directory.replace({
    expectedRevision: null,
    directory: {
      version: "oaath.service-directory/v1",
      applications: [{ clientId: "client-a", applicationId: "app-1", applicationName: "Example" }],
      workspaces: [{ workspaceId: "team-1", kind: "team" }],
      memberships: [{ workspaceId: "team-1", clientId: "client-a", subject: "subject-1" }],
      ownerDevices: [{ workspaceId: "team-1", ownerDeviceId: "phone-1", subject: "subject-1" }],
      accounts: [
        {
          workspaceId: "team-1",
          accountId: "account-1",
          ownerDeviceId: "phone-1",
          account: scope.logicalAccount,
          ownerValidator: null,
          chainIds: [31337],
        },
      ],
      selections: [],
    },
  });
  const clock = createTestClock(150_000);
  const kms = createTestKms();
  const harness: Harness = {
    store,
    clock,
    kms,
    handler: createRelayHandler({
      store,
      clock,
      kms,
      authentication: createTestAuthentication(),
      ownerRouting: directory,
    }),
  };
  const created = await createRequest(harness, JSON.stringify(scope));
  const permissionRequest = { ...scope, requestId: created.requestId };
  await approve(
    harness,
    created.requestId,
    JSON.stringify({
      version: "oaath.permission-decision/v1",
      kind: "approve",
      requestId: created.requestId,
      requestHash: hashPermissionRequest(permissionRequest),
      decidedAt: 150,
      approvedPolicy: scope.policy,
      capabilityHash: `0x${"ab".repeat(32)}`,
    }),
  );
  const { name: _name, ...operation } = source.valid[0];
  const signingRequest = parseKernelV4RevocationSigningRequest({
    version: "oaath.kernel-revocation-signing-request/v1",
    kind: "kernel-revocation",
    permissionRequest,
    install: {
      ...source.installProjection.scope.request,
      signer: { ...source.installProjection.scope.request.signer, ownerCredential },
    },
    ...operation,
  });
  const prepare = vi.fn(async () => signingRequest);
  const input = {
    store,
    clock,
    kms,
    directory,
    caller:
      CALLERS.get(CLIENT_TOKEN) ??
      (() => {
        throw new Error("missing client");
      })(),
    grantId: created.requestId,
    chainId: 31337,
    requestTtlMs: 60_000,
    prepare,
  };
  const artifact = (request: KernelV4RevocationSigningRequest = signingRequest) =>
    serializeOwnerSigningArtifact({
      version: "oaath.owner-signing-artifact/v1",
      kind: "p256",
      requestHash: hashKernelV4RevocationSigningRequest(request),
      signature: `0x${p256.sign(hexToBytes(request.expectedDigest.slice(2)), key, { prehash: false, lowS: true }).toCompactHex()}`,
    });
  return { harness, input, prepare, signingRequest, artifact, erase: () => key.fill(0) };
}
