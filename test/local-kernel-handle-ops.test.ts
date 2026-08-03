import { KernelV3ExecuteAbi } from "@zerodev/sdk";
import { decodeFunctionData, type Hex } from "viem";
import { entryPoint07Abi } from "viem/account-abstraction";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { describe, expect, it } from "vitest";
import {
  createLocalKernelHandleOpsAdapter,
  createLocalKernelPermissionUninstallAdapter,
  type OgpKernelHandleOpsAdapterError,
  type PreparedUserOperation,
  prepareUserOperation,
} from "../src/index.js";

const key = { grantId: "kernel-grant", chainId: 31_337 } as const;
const entryPoint = `0x${"11".repeat(20)}` as const;
const account = `0x${"22".repeat(20)}` as const;
const validator = `0x${"33".repeat(20)}` as const;
const target = `0x${"44".repeat(20)}` as const;
const submitter = `0x${"55".repeat(20)}` as const;
const transactionHash = `0x${"66".repeat(32)}` as const;
const permissionSigner = `0x${"66".repeat(20)}` as const;
const permissionOperator = `0x${"77".repeat(20)}` as const;
const noHook = `0x${"00".repeat(19)}01` as const;
const permissionId = "0x6eea81c7" as const;
const validationId = `0x02${permissionId.slice(2)}${"00".repeat(16)}` as const;

const gas = {
  callGasLimit: "150000",
  verificationGasLimit: "300000",
  preVerificationGas: "75000",
  maxFeePerGas: "2000000000",
  maxPriorityFeePerGas: "1000000000",
} as const;

interface Control {
  reads: unknown[];
  signs: unknown[];
  sends: unknown[];
  readCloses: number;
  signerCloses: number;
  submitterCloses: number;
  readCloseFailures: number;
  signerCloseFailures: number;
  submitterCloseFailures: number;
  nonce: string;
  result?: unknown;
}

function control(): Control {
  return {
    reads: [],
    signs: [],
    sends: [],
    readCloses: 0,
    signerCloses: 0,
    submitterCloses: 0,
    readCloseFailures: 0,
    signerCloseFailures: 0,
    submitterCloseFailures: 0,
    nonce: "7",
  };
}

async function fixture(
  input: {
    chainId?: number;
    control?: Control;
    readResults?: Readonly<Record<string, unknown>>;
    sign?: (userOperationHash: Hex) => Promise<unknown>;
  } = {},
) {
  const state = input.control ?? control();
  const ownerAccount = privateKeyToAccount(generatePrivateKey());
  const operationKey = { ...key, chainId: input.chainId ?? key.chainId };
  const adapter = createLocalKernelHandleOpsAdapter({
    profile: "kernel-v3.3-ecdsa-owner",
    key: operationKey,
    entryPoint: { version: "0.7", address: entryPoint },
    kernel: { account, rootValidator: validator, owner: ownerAccount.address.toLowerCase() },
    call: { target, value: "9", data: "0x1234" },
    gas,
    handleOpsGasLimit: "1000000",
    preparationReads: {
      async read(request: { type: string; chainId: number }) {
        state.reads.push(request);
        if (input.readResults && request.type in input.readResults) {
          return input.readResults[request.type];
        }
        if (request.type === "chain_id") return request.chainId;
        if (request.type === "code") return "0x01";
        if (request.type === "entry_point_nonce") return state.nonce;
        if (request.type === "kernel_root_validator") {
          return `0x01${validator.slice(2)}`;
        }
        if (request.type === "kernel_ecdsa_owner") return ownerAccount.address.toLowerCase();
        throw new Error("unexpected semantic read");
      },
      async close() {
        state.readCloses += 1;
        if (state.readCloseFailures > 0) {
          state.readCloseFailures -= 1;
          throw new Error("private read cleanup failure");
        }
      },
    },
    userOperationSigner: {
      address: ownerAccount.address.toLowerCase(),
      async signDigest(request: { userOperationHash: `0x${string}` }) {
        state.signs.push(request);
        return input.sign
          ? input.sign(request.userOperationHash)
          : ownerAccount.sign({ hash: request.userOperationHash });
      },
      async close() {
        state.signerCloses += 1;
        if (state.signerCloseFailures > 0) {
          state.signerCloseFailures -= 1;
          throw new Error("private signer cleanup failure");
        }
      },
    },
    handleOpsSubmitter: {
      address: submitter,
      async sendHandleOps(request: {
        chainId: number;
        entryPoint: `0x${string}`;
        submitter: `0x${string}`;
        userOperationHash: `0x${string}`;
      }) {
        state.sends.push(request);
        return (
          state.result ?? {
            chainId: request.chainId,
            entryPoint: request.entryPoint,
            submitter: request.submitter,
            userOperationHash: request.userOperationHash,
            transactionHash,
          }
        );
      },
      async close() {
        state.submitterCloses += 1;
        if (state.submitterCloseFailures > 0) {
          state.submitterCloseFailures -= 1;
          throw new Error("private submitter cleanup failure");
        }
      },
    },
  });
  return { adapter, state, operationKey, owner: ownerAccount.address.toLowerCase() };
}

async function preparedFrom(
  adapter: Awaited<ReturnType<typeof fixture>>["adapter"],
  operationKey: Readonly<{ grantId: string; chainId: number }> = key,
) {
  return (await adapter.preparation.prepare({
    kind: "execution",
    key: operationKey,
  })) as PreparedUserOperation;
}

function reprepare(
  prepared: PreparedUserOperation,
  change: (input: {
    kind: "execution";
    grantId: string;
    chainId: number;
    entryPoint: PreparedUserOperation["entryPoint"];
    userOperation: PreparedUserOperation["userOperation"];
  }) => void,
): PreparedUserOperation {
  const input = {
    kind: "execution" as const,
    grantId: prepared.grantId,
    chainId: prepared.chainId,
    entryPoint: { ...prepared.entryPoint },
    userOperation: { ...prepared.userOperation },
  };
  change(input);
  return prepareUserOperation(input);
}

async function expectAdapterError(
  action: () => Promise<unknown>,
  code: OgpKernelHandleOpsAdapterError["code"],
) {
  await expect(action()).rejects.toMatchObject({
    name: "OgpKernelHandleOpsAdapterError",
    code,
  });
}

describe("local Kernel handleOps adapter", () => {
  it.each([1, 31_337, 9_999_999])(
    "binds concrete chainId %s without a supported-chain policy",
    async (chainId) => {
      const { adapter, state, operationKey, owner } = await fixture({ chainId });
      const prepared = await preparedFrom(adapter, operationKey);

      expect(prepared).toMatchObject({
        kind: "execution",
        grantId: operationKey.grantId,
        chainId,
        entryPoint: { version: "0.7", address: entryPoint },
        userOperation: {
          sender: account,
          nonce: "7",
          callGasLimit: gas.callGasLimit,
          factory: null,
          paymaster: null,
        },
      });
      expect(prepared.userOperation.callData).not.toBe("0x");
      expect(state.reads).toEqual([
        { type: "chain_id", chainId },
        { type: "code", chainId, address: entryPoint },
        { type: "code", chainId, address: account },
        { type: "code", chainId, address: validator },
        { type: "kernel_root_validator", chainId, account },
        { type: "kernel_ecdsa_owner", chainId, validator, account },
        { type: "entry_point_nonce", chainId, entryPoint, account, nonceKey: "0" },
      ]);
      expect(owner).not.toBe(submitter);
      expect(state.signs).toHaveLength(0);
      expect(state.sends).toHaveLength(0);
    },
  );

  it("rejects a chain registry at the exact configuration boundary", async () => {
    const { adapter } = await fixture();
    await adapter.preparation.close();
    await adapter.submission.close();

    const base = await fixture();
    const configuration = {
      profile: "kernel-v3.3-ecdsa-owner",
      key,
      entryPoint: { version: "0.7", address: entryPoint },
      kernel: { account, rootValidator: validator, owner: base.owner },
      call: { target, value: "0", data: "0x" },
      gas,
      handleOpsGasLimit: "1000000",
      preparationReads: { read: async () => null, close: async () => {} },
      userOperationSigner: {
        address: base.owner,
        signDigest: async () => "0x",
        close: async () => {},
      },
      handleOpsSubmitter: {
        address: submitter,
        sendHandleOps: async () => null,
        close: async () => {},
      },
      supportedChains: [key.chainId],
    };
    expect(() => createLocalKernelHandleOpsAdapter(configuration)).toThrowError(
      expect.objectContaining({ code: "kernel_handle_ops_capability_invalid" }),
    );
    await base.adapter.preparation.close();
    await base.adapter.submission.close();
  });

  it.each([
    ["chain_id", key.chainId + 1],
    ["code", "0x"],
    ["kernel_root_validator", `0x01${"77".repeat(20)}`],
    ["kernel_ecdsa_owner", `0x${"88".repeat(20)}`],
    ["entry_point_nonce", "01"],
  ])("rejects contradictory %s evidence before authority is reachable", async (type, result) => {
    const { adapter, state } = await fixture({ readResults: { [type]: result } });
    await expectAdapterError(() => preparedFrom(adapter), "kernel_handle_ops_preparation_rejected");
    expect(state.signs).toHaveLength(0);
    expect(state.sends).toHaveLength(0);
  });

  it("signs only the exact snapshot returned by preparation and submits a zero-argument session once", async () => {
    const { adapter, state, operationKey } = await fixture();
    const prepared = await preparedFrom(adapter, operationKey);
    const session = (await adapter.submission.openSubmission(prepared)) as {
      submit(): Promise<unknown>;
      close(): Promise<void>;
    };

    expect(state.signs).toEqual([
      {
        chainId: operationKey.chainId,
        entryPoint,
        account,
        userOperationHash: prepared.userOperationHash,
      },
    ]);
    expect(session.submit).toHaveLength(0);
    await expect(session.submit()).resolves.toEqual({
      userOperationHash: prepared.userOperationHash,
    });
    expect(state.sends).toHaveLength(1);
    const request = state.sends[0] as { calldata: `0x${string}` };
    expect(decodeFunctionData({ abi: entryPoint07Abi, data: request.calldata }).functionName).toBe(
      "handleOps",
    );
    await expectAdapterError(() => session.submit(), "kernel_handle_ops_closed");
  });

  it("rejects every hash-bound mutation before a signer can run", async () => {
    const { adapter, state, operationKey } = await fixture();
    const prepared = await preparedFrom(adapter, operationKey);
    const mutations: PreparedUserOperation[] = [
      reprepare(prepared, (value) => {
        value.chainId += 1;
      }),
      reprepare(prepared, (value) => {
        value.entryPoint = { ...value.entryPoint, address: `0x${"77".repeat(20)}` };
      }),
      reprepare(prepared, (value) => {
        value.userOperation = { ...value.userOperation, sender: `0x${"88".repeat(20)}` };
      }),
      reprepare(prepared, (value) => {
        value.userOperation = { ...value.userOperation, nonce: "8" };
      }),
      reprepare(prepared, (value) => {
        value.userOperation = { ...value.userOperation, callData: "0xabcd" };
      }),
      reprepare(prepared, (value) => {
        value.userOperation = { ...value.userOperation, callGasLimit: "150001" };
      }),
    ];

    for (const mutation of mutations) {
      await expectAdapterError(
        () => adapter.submission.openSubmission(mutation),
        "kernel_handle_ops_identity_mismatch",
      );
    }
    expect(state.signs).toHaveLength(0);
    expect(state.sends).toHaveLength(0);
  });

  it("fails closed on a signature from any identity other than the prepared Kernel owner", async () => {
    const wrongSigner = privateKeyToAccount(generatePrivateKey());
    const { adapter, state } = await fixture({
      sign: (userOperationHash) => wrongSigner.sign({ hash: userOperationHash }),
    });
    const prepared = await preparedFrom(adapter);
    await expectAdapterError(
      () => adapter.submission.openSubmission(prepared),
      "kernel_handle_ops_signature_invalid",
    );
    expect(state.sends).toHaveLength(0);
  });

  it("rejects contradictory or accessor-backed send evidence after exactly one send", async () => {
    const state = control();
    const { adapter } = await fixture({ control: state });
    const prepared = await preparedFrom(adapter);
    state.result = {
      chainId: key.chainId,
      entryPoint,
      submitter,
      userOperationHash: `0x${"77".repeat(32)}`,
      transactionHash,
    };
    const contradictory = (await adapter.submission.openSubmission(prepared)) as {
      submit(): Promise<unknown>;
    };
    await expectAdapterError(() => contradictory.submit(), "kernel_handle_ops_result_invalid");
    expect(state.sends).toHaveLength(1);

    const next = await fixture();
    const nextPrepared = await preparedFrom(next.adapter);
    let getterCalls = 0;
    next.state.result = Object.defineProperty({}, "chainId", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return key.chainId;
      },
    });
    const accessor = (await next.adapter.submission.openSubmission(nextPrepared)) as {
      submit(): Promise<unknown>;
    };
    await expectAdapterError(() => accessor.submit(), "kernel_handle_ops_result_invalid");
    expect(getterCalls).toBe(0);
  });

  it("attempts independent cleanup and retries only failed resources", async () => {
    const state = control();
    state.readCloseFailures = 1;
    state.signerCloseFailures = 1;
    state.submitterCloseFailures = 1;
    const { adapter } = await fixture({ control: state });

    await expectAdapterError(() => adapter.preparation.close(), "kernel_handle_ops_close_failed");
    await adapter.preparation.close();
    expect(state.readCloses).toBe(2);

    await expectAdapterError(() => adapter.submission.close(), "kernel_handle_ops_close_failed");
    expect(state.signerCloses).toBe(1);
    expect(state.submitterCloses).toBe(1);
    await adapter.submission.close();
    expect(state.signerCloses).toBe(2);
    expect(state.submitterCloses).toBe(2);
  });
});

async function permissionFixture(readResults: Readonly<Record<string, unknown>> = {}) {
  const state = control();
  const ownerAccount = privateKeyToAccount(generatePrivateKey());
  const permission = { signer: permissionSigner, operator: permissionOperator };
  const adapter = createLocalKernelPermissionUninstallAdapter({
    profile: "kernel-v3.3-permission-uninstall",
    key,
    entryPoint: { version: "0.7", address: entryPoint },
    kernel: { account, rootValidator: validator, owner: ownerAccount.address.toLowerCase() },
    permission,
    gas,
    handleOpsGasLimit: "1000000",
    preparationReads: {
      async read(request: { type: string; chainId: number }) {
        state.reads.push(request);
        if (request.type in readResults) return readResults[request.type];
        if (request.type === "chain_id") return request.chainId;
        if (request.type === "code") return "0x01";
        if (request.type === "kernel_root_validator") return `0x01${validator.slice(2)}`;
        if (request.type === "kernel_ecdsa_owner") return ownerAccount.address.toLowerCase();
        if (request.type === "kernel_validation_config") return { nonce: "1", hook: noHook };
        if (request.type === "kernel_permission_config") {
          return { permissionFlag: "0x0000", signer: permissionSigner, policyCount: 0 };
        }
        if (request.type === "kernel_allowed_selector") return true;
        if (request.type === "multi_chain_signer_owner") return permissionOperator;
        if (request.type === "entry_point_nonce") return state.nonce;
        throw new Error("unexpected permission read");
      },
      async close() {
        state.readCloses += 1;
      },
    },
    userOperationSigner: {
      address: ownerAccount.address.toLowerCase(),
      async signDigest(request: { userOperationHash: Hex }) {
        state.signs.push(request);
        return ownerAccount.sign({ hash: request.userOperationHash });
      },
      async close() {
        state.signerCloses += 1;
      },
    },
    handleOpsSubmitter: {
      address: submitter,
      async sendHandleOps(request: {
        chainId: number;
        entryPoint: `0x${string}`;
        submitter: `0x${string}`;
        userOperationHash: Hex;
      }) {
        state.sends.push(request);
        return {
          chainId: request.chainId,
          entryPoint: request.entryPoint,
          submitter: request.submitter,
          userOperationHash: request.userOperationHash,
          transactionHash,
        };
      },
      async close() {
        state.submitterCloses += 1;
      },
    },
  });
  return { adapter, permission, state };
}

describe("local Kernel permission uninstall adapter", () => {
  it("derives and prepares the exact Kernel permission uninstall call", async () => {
    const { adapter, permission, state } = await permissionFixture();
    permission.operator = `0x${"88".repeat(20)}`;

    expect(adapter.descriptor).toEqual({
      kind: "kernel-v3.3-permission-uninstall",
      grantId: key.grantId,
      chainId: key.chainId,
      entryPoint,
      account,
      permissionId,
      validationId,
      signer: permissionSigner,
      operator: permissionOperator,
    });
    const prepared = (await adapter.preparation.prepare({
      kind: "revocation",
      key,
    })) as PreparedUserOperation;
    expect(prepared).toMatchObject({
      kind: "revocation",
      grantId: key.grantId,
      chainId: key.chainId,
      userOperation: { sender: account, nonce: "7" },
    });

    const execution = decodeFunctionData({
      abi: KernelV3ExecuteAbi,
      data: prepared.userOperation.callData,
    });
    expect(execution.functionName).toBe("execute");
    const executionCalldata = execution.args[1] as Hex;
    expect(`0x${executionCalldata.slice(2, 42)}`).toBe(account);
    expect(BigInt(`0x${executionCalldata.slice(42, 106)}`)).toBe(0n);
    const uninstall = decodeFunctionData({
      abi: [
        {
          type: "function",
          name: "uninstallValidation",
          stateMutability: "payable",
          inputs: [
            { name: "vId", type: "bytes21" },
            { name: "deinitData", type: "bytes" },
            { name: "hookDeinitData", type: "bytes" },
          ],
          outputs: [],
        },
      ] as const,
      data: `0x${executionCalldata.slice(106)}`,
    });
    expect(uninstall.args).toEqual([
      validationId,
      "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000",
      "0x",
    ]);
    expect(state.reads).toEqual([
      { type: "chain_id", chainId: key.chainId },
      { type: "code", chainId: key.chainId, address: entryPoint },
      { type: "code", chainId: key.chainId, address: account },
      { type: "code", chainId: key.chainId, address: validator },
      { type: "kernel_root_validator", chainId: key.chainId, account },
      { type: "kernel_ecdsa_owner", chainId: key.chainId, validator, account },
      { type: "code", chainId: key.chainId, address: permissionSigner },
      { type: "kernel_validation_config", chainId: key.chainId, account, validationId },
      { type: "kernel_permission_config", chainId: key.chainId, account, permissionId },
      {
        type: "kernel_allowed_selector",
        chainId: key.chainId,
        account,
        validationId,
        selector: "0xe9ae5c53",
      },
      {
        type: "multi_chain_signer_owner",
        chainId: key.chainId,
        signer: permissionSigner,
        account,
        permissionId,
      },
      { type: "entry_point_nonce", chainId: key.chainId, entryPoint, account, nonceKey: "0" },
    ]);
    expect(state.signs).toHaveLength(0);
    expect(state.sends).toHaveLength(0);
    const session = (await adapter.submission.openSubmission(prepared)) as {
      submit(): Promise<unknown>;
    };
    await expect(session.submit()).resolves.toEqual({
      userOperationHash: prepared.userOperationHash,
    });
    expect(state.signs).toHaveLength(1);
    expect(state.sends).toHaveLength(1);
  });

  it.each([
    ["kernel_validation_config", { nonce: "1", hook: `0x${"00".repeat(20)}` }],
    [
      "kernel_permission_config",
      { permissionFlag: "0x0000", signer: `0x${"00".repeat(20)}`, policyCount: 0 },
    ],
    [
      "kernel_permission_config",
      { permissionFlag: "0x0000", signer: permissionSigner, policyCount: 1 },
    ],
    ["kernel_allowed_selector", false],
    ["multi_chain_signer_owner", `0x${"88".repeat(20)}`],
  ])("rejects contradictory installed %s evidence before signing", async (type, result) => {
    const { adapter, state } = await permissionFixture({ [type]: result });
    await expectAdapterError(
      () => adapter.preparation.prepare({ kind: "revocation", key }),
      "kernel_handle_ops_preparation_rejected",
    );
    expect(state.signs).toHaveLength(0);
    expect(state.sends).toHaveLength(0);
  });

  it("maps hostile permission evidence to a structured rejection without invoking authority", async () => {
    const hostile = new Proxy(
      {},
      {
        ownKeys() {
          throw new Error("private provider detail");
        },
      },
    );
    const { adapter, state } = await permissionFixture({
      kernel_permission_config: hostile,
    });

    await expectAdapterError(
      () => adapter.preparation.prepare({ kind: "revocation", key }),
      "kernel_handle_ops_preparation_rejected",
    );
    expect(state.signs).toHaveLength(0);
    expect(state.sends).toHaveLength(0);
  });

  it("rejects execution requests and arbitrary-call or chain-list configuration", async () => {
    const { adapter } = await permissionFixture();
    await expectAdapterError(
      () => adapter.preparation.prepare({ kind: "execution", key }),
      "kernel_handle_ops_preparation_rejected",
    );

    const configuration = {
      profile: "kernel-v3.3-permission-uninstall",
      key,
      entryPoint: { version: "0.7", address: entryPoint },
      kernel: { account, rootValidator: validator, owner: target },
      permission: { signer: permissionSigner, operator: permissionOperator },
      gas,
      handleOpsGasLimit: "1000000",
      preparationReads: { read: async () => null, close: async () => {} },
      userOperationSigner: { address: target, signDigest: async () => "0x", close: async () => {} },
      handleOpsSubmitter: {
        address: submitter,
        sendHandleOps: async () => null,
        close: async () => {},
      },
      call: { target, value: "0", data: "0x" },
      supportedChains: [key.chainId],
    };
    expect(() => createLocalKernelPermissionUninstallAdapter(configuration)).toThrowError(
      expect.objectContaining({ code: "kernel_handle_ops_capability_invalid" }),
    );
  });
});
