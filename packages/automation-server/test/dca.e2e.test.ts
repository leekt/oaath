/**
 * The automation service end to end, all on loopback: the real relay binary
 * as the OAAth issuer, two service replicas over one throwaway PostgreSQL,
 * and Anvil with the Kernel v4 stack, Uniswap v3 and the examples/dca
 * contracts. Only the ERC-4337 bundler is a fixture: it hands each operation
 * to the EntryPoint, and it can hold one back to model a missing receipt.
 *
 * The account root approves the plan's Grant through the portal API exactly as
 * the portal does: sign in, create an account, prepare, sign, decide. The
 * service then runs the setup operation (deploy + enable + approve + open) and
 * two due occurrences (real swaps). Finality is held throughout, as on a rollup
 * awaiting L1: the plan activates once setup is included, and the first
 * occurrence is sent on its own Kernel nonce lane while setup is not final. It
 * observes a held operation repeatedly without sending it again, and while the
 * first occurrence is included but not final, the second is sent on time on
 * its own lane.
 *
 * Opt-in: `bun run --filter @oaath/automation-server test:e2e` (needs cargo,
 * Anvil and PostgreSQL binaries).
 */
import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { entryPointAbi } from "@oaath/protocol";
import {
  kernelDeployment,
  kernelPermissionCapabilityHash,
  parseKernelPermissionApproval,
} from "@oaath/sdk/kernel";
import { generatePrivateKey, privateKeyToAccount } from "cetane/accounts";
import { getSigningHash, type Operation, toPackedUserOperation } from "cetane/execution/erc4337";
import { encodeFunctionData as cetaneEncode } from "cetane/utils";
import {
  createPublicClient,
  createWalletClient,
  decodeEventLog,
  encodeFunctionData,
  type Hex,
  http,
  parseAbi,
} from "viem";
import { privateKeyToAccount as viemAccount, generatePrivateKey as viemKey } from "viem/accounts";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { dcaAutomation } from "../../../examples/dca/dca.automation.js";
import v33 from "../../sdk/test/fixtures/kernel-v33-deployments.json" with { type: "json" };
import { readLocalOperationReceipt } from "../../testing/src/anvil-observation.mjs";
import { deployKernelStack, startAnvil } from "../../testing/src/anvil-process.mjs";
import { configFromEnv } from "../src/config.js";
import { type AutomationService, startAutomationService } from "../src/service.js";
import { startCluster, type TestCluster } from "./support/postgres.js";

const ENABLED = process.env.OAATH_AUTOMATION_E2E === "1";
const CHAIN_ID = 421_614;
const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const EXAMPLES = join(ROOT, "examples");
const APP_TOKEN = randomBytes(32).toString("hex");
const artifact = (path: string) => JSON.parse(readFileSync(join(EXAMPLES, path), "utf8"));
const uniswap = (path: string) => artifact(`node_modules/@uniswap/${path}`);

type Anvil = Awaited<ReturnType<typeof startAnvil>>;
type Stack = Awaited<ReturnType<typeof deployKernelStack>>;

async function freePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as { port: number };
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function until<T>(
  read: () => Promise<T | null | undefined | false>,
  label: string,
  seconds = 120,
) {
  for (let elapsed = 0; elapsed < seconds * 4; elapsed += 1) {
    const value = await read();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`timed out waiting for ${label}`);
}

/** Tokens, feeds, a seeded Uniswap v3 pool, and the shared DCA executor. */
async function deployMarket(anvil: Anvil) {
  const deployer = viemAccount(viemKey());
  await anvil.rpc("anvil_setBalance", [deployer.address, "0x3635c9adc5dea00000"]);
  const client = createPublicClient({ transport: http(anvil.url) });
  const wallet = createWalletClient({ account: deployer, transport: http(anvil.url) });
  const deploy = async (contract: { abi: unknown; bytecode: unknown }, args: unknown[] = []) => {
    const hash = await wallet.deployContract({
      abi: contract.abi as never,
      bytecode: (typeof contract.bytecode === "string"
        ? contract.bytecode
        : (contract.bytecode as { object: string }).object) as Hex,
      args: args as never,
      chain: null,
      gas: 25_000_000n,
    });
    const receipt = await client.waitForTransactionReceipt({ hash });
    if (!receipt.contractAddress || receipt.status !== "success") throw new Error("deploy failed");
    return receipt.contractAddress.toLowerCase() as Hex;
  };
  const send = async (to: Hex, data: Hex) => {
    const hash = await wallet.sendTransaction({ to, data, chain: null, gas: 15_000_000n });
    if ((await client.waitForTransactionReceipt({ hash })).status !== "success")
      throw new Error("fixture transaction failed");
  };
  const token = artifact("dca/contracts/artifacts/FixtureToken.json");
  const feed = artifact("dca/contracts/artifacts/FixtureFeed.json");
  const sellToken = await deploy(token, [6]);
  const buyToken = await deploy(token, [18]);
  const sellFeed = await deploy(feed, [100_000_000n]);
  const buyFeed = await deploy(feed, [200_000_000_000n]);
  const managerArtifact = uniswap(
    "v3-periphery/artifacts/contracts/NonfungiblePositionManager.sol/NonfungiblePositionManager.json",
  );
  const factory = await deploy(
    uniswap("v3-core/artifacts/contracts/UniswapV3Factory.sol/UniswapV3Factory.json"),
  );
  const zero = "0x0000000000000000000000000000000000000000";
  const manager = await deploy(managerArtifact, [factory, buyToken, zero]);
  const router = await deploy(
    uniswap("swap-router-contracts/artifacts/contracts/SwapRouter02.sol/SwapRouter02.json"),
    [zero, factory, manager, buyToken],
  );
  for (const [address, amount] of [
    [sellToken, 2_000_000n * 10n ** 6n],
    [buyToken, 1_000n * 10n ** 18n],
  ] as const) {
    await send(
      address,
      encodeFunctionData({
        abi: token.abi,
        functionName: "mint",
        args: [deployer.address, amount],
      }),
    );
    await send(
      address,
      encodeFunctionData({ abi: token.abi, functionName: "approve", args: [manager, amount] }),
    );
  }
  const [token0, token1] = [sellToken, buyToken].sort() as [Hex, Hex];
  const sqrt = (n: bigint) => {
    let x = n;
    let y = (x + 1n) / 2n;
    while (y < x) {
      x = y;
      y = (x + n / x) / 2n;
    }
    return x;
  };
  const sellFirst = sellToken === token0;
  // 1 sell (6 decimals) = 1/2000 buy (18 decimals), matching the two feeds.
  const price = sellFirst ? 500_000_000n << 192n : (1n << 192n) / 500_000_000n;
  await send(
    manager,
    encodeFunctionData({
      abi: managerArtifact.abi,
      functionName: "createAndInitializePoolIfNecessary",
      args: [token0, token1, 3000, sqrt(price)],
    }),
  );
  await send(
    manager,
    encodeFunctionData({
      abi: managerArtifact.abi,
      functionName: "mint",
      args: [
        {
          token0,
          token1,
          fee: 3000,
          tickLower: -887220,
          tickUpper: 887220,
          amount0Desired: sellFirst ? 1_000_000n * 10n ** 6n : 500n * 10n ** 18n,
          amount1Desired: sellFirst ? 500n * 10n ** 18n : 1_000_000n * 10n ** 6n,
          amount0Min: 0n,
          amount1Min: 0n,
          recipient: deployer.address,
          deadline: BigInt(Math.floor(Date.now() / 1000) + 3600),
        },
      ],
    }),
  );
  const dca = await deploy(artifact("dca/contracts/artifacts/DcaExecutor.json"), [
    sellToken,
    buyToken,
    router,
    3000,
    sellFeed,
    buyFeed,
    3600,
  ]);
  return {
    sellToken,
    buyToken,
    dca,
    mint: (to: Hex, amount: bigint) =>
      send(
        sellToken,
        encodeFunctionData({ abi: token.abi, functionName: "mint", args: [to, amount] }),
      ),
  };
}

/**
 * The bundler fixture: estimates generously, submits through
 * `EntryPoint.handleOps`, and reads receipts back from chain evidence. While
 * `hold` is set, an accepted operation is kept out of the chain. While
 * `holdFinality` is set, inclusion mines no further blocks, so Anvil's
 * `finalized` tag (two blocks behind) stays below it, as on a rollup awaiting L1.
 */
async function startBundler(anvil: Anvil, stack: Stack) {
  const deployment = kernelDeployment({ chainId: CHAIN_ID });
  const entryPoint = deployment.entryPoint.address;
  const state = {
    sends: 0,
    hold: false,
    holdFinality: false,
    held: [] as Operation[],
    receiptReads: new Map<string, number>(),
  };
  const include = async (operation: Operation) => {
    const hash = await stack.wallet.sendTransaction({
      account: stack.submitter,
      to: entryPoint,
      gas: 12_000_000n,
      data: cetaneEncode({
        abi: entryPointAbi,
        functionName: "handleOps",
        args: [
          [toPackedUserOperation(operation, deployment.entryPoint.version)],
          stack.submitter.address,
        ],
      }),
    });
    await anvil.client.waitForTransactionReceipt({ hash });
    if (!state.holdFinality) await anvil.rpc("anvil_mine", ["0x3"]);
  };
  const server: Server = createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk as Buffer);
    const { id, method, params } = JSON.parse(Buffer.concat(chunks).toString());
    const answer = (result: unknown) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ jsonrpc: "2.0", id, result }));
    };
    try {
      if (method === "eth_chainId") return answer(`0x${CHAIN_ID.toString(16)}`);
      if (method === "eth_supportedEntryPoints") return answer([entryPoint]);
      if (method === "eth_estimateUserOperationGas")
        return answer({
          callGasLimit: "0x4c4b40",
          verificationGasLimit: "0x2dc6c0",
          preVerificationGas: "0x249f0",
        });
      if (method === "eth_getUserOperationReceipt") {
        state.receiptReads.set(params[0], (state.receiptReads.get(params[0]) ?? 0) + 1);
        const receipt = await readLocalOperationReceipt(anvil, entryPoint, params[0]);
        return answer(
          receipt === null
            ? null
            : {
                userOpHash: receipt.userOperationHash,
                entryPoint: receipt.entryPoint,
                sender: receipt.sender,
                nonce: receipt.nonce,
                actualGasCost: receipt.actualGasCost,
                actualGasUsed: receipt.actualGasUsed,
                success: receipt.success,
                receipt: {
                  transactionHash: receipt.transactionHash,
                  blockHash: receipt.blockHash,
                  blockNumber: receipt.blockNumber,
                },
              },
        );
      }
      if (method === "eth_sendUserOperation") {
        state.sends += 1;
        const wire = params[0];
        const operation = {
          ...wire,
          ...Object.fromEntries(
            [
              "nonce",
              "callGasLimit",
              "verificationGasLimit",
              "preVerificationGas",
              "maxFeePerGas",
              "maxPriorityFeePerGas",
            ].map((key) => [key, BigInt(wire[key])]),
          ),
        } as Operation;
        if (state.hold) state.held.push(operation);
        else await include(operation);
        return answer(
          getSigningHash(operation, CHAIN_ID, entryPoint, deployment.entryPoint.version),
        );
      }
      response.writeHead(200, { "content-type": "application/json" });
      response.end(
        JSON.stringify({ jsonrpc: "2.0", id, error: { code: -32601, message: "unsupported" } }),
      );
    } catch {
      response.writeHead(500).end();
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as { port: number };
  return {
    url: `http://127.0.0.1:${port}`,
    state,
    async release() {
      state.hold = false;
      for (const operation of state.held.splice(0)) await include(operation);
    },
    async finalize() {
      state.holdFinality = false;
      await anvil.rpc("anvil_mine", ["0x3"]);
    },
    close: () => server.close(),
  };
}

/** The relay binary on loopback, its issuer equal to its own base URL. */
async function startRelay(): Promise<{ url: string; process: ChildProcess }> {
  const relayDir = join(ROOT, "relay");
  const cargo = [process.env.CARGO, join(homedir(), ".cargo/bin/cargo")].find(
    (path) => path !== undefined && existsSync(path),
  );
  const build = spawnSync(cargo ?? "cargo", ["build", "-q", "-p", "oaath-relay"], {
    cwd: relayDir,
    stdio: "inherit",
  });
  if (build.status !== 0) throw new Error("cargo build -p oaath-relay failed");
  const work = mkdtempSync(join(tmpdir(), "oaath-automation-e2e-"));
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  writeFileSync(join(work, "id-token.pem"), privateKey.export({ type: "pkcs8", format: "pem" }));
  const port = await freePort();
  const url = `http://127.0.0.1:${port}`;
  const child = spawn(join(relayDir, "target/debug/oaath-relay"), [], {
    stdio: ["ignore", "ignore", "inherit"],
    env: {
      PATH: process.env.PATH ?? "",
      RUST_LOG: "warn",
      OAATH_LISTEN: `127.0.0.1:${port}`,
      OAATH_KMS_KEY: randomBytes(32).toString("hex"),
      OAATH_ISSUER: url,
      OAATH_ID_TOKEN_KEY: join(work, "id-token.pem"),
    },
  });
  await until(async () => {
    if (child.exitCode !== null) throw new Error("the relay exited");
    return (await fetch(`${url}/.well-known/openid-configuration`).catch(() => null))?.ok;
  }, "the relay");
  return { url, process: child };
}

async function json(response: Response) {
  const body = await response.json();
  if (!response.ok) throw new Error(`${response.status} ${JSON.stringify(body)}`);
  return body;
}

/** An ECDSA account root, signed in to the portal API, with one derived account. */
async function portalRoot(relay: string) {
  const root = privateKeyToAccount(generatePrivateKey());
  const post = (path: string, body: unknown, cookie?: string) =>
    fetch(`${relay}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", ...(cookie ? { cookie } : {}) },
      body: JSON.stringify(body),
    });
  const { signer_id: signerId } = await json(
    await post("/portal/signers", {
      profile: {
        version: "oaath.owner-credential-profile/v1",
        kind: "ecdsa",
        address: root.address.toLowerCase(),
      },
    }),
  );
  const challenge = await json(await post("/portal/sessions/challenge", { signer_id: signerId }));
  const signedIn = await post("/portal/sessions", {
    signer_id: signerId,
    nonce: challenge.nonce,
    signature: await root.signMessage({ message: challenge.message }),
  });
  await json(signedIn.clone());
  const cookie = (signedIn.headers.get("set-cookie") ?? "").split(";")[0] as string;
  const account = await json(
    await post(
      "/portal/accounts",
      { root_signer_id: signerId, creation_key: randomBytes(16).toString("hex") },
      cookie,
    ),
  );
  /** Approves one pushed Grant as the portal does and answers the issuer's redirect. */
  async function approve(authorizationUrl: string): Promise<string> {
    const requestUri = new URL(authorizationUrl).searchParams.get("request_uri") as string;
    const id = requestUri.split(":").pop() as string;
    const selection = { signer_id: signerId, account_id: account.account_id };
    const prepared = await json(
      await post(`/portal/transactions/${id}/prepare`, selection, cookie),
    );
    const signing = prepared.signing_request;
    const enableSignature = await root.sign({ hash: signing.expectedDigest });
    const installApproval = {
      version: "oaath.kernel.all-chain-approval/v1",
      account: signing.signer.account,
      installNonce: signing.typedData.message.nonce,
      packages: signing.typedData.message.packages.map((install: { moduleType: string }) => ({
        ...install,
        moduleType: Number(install.moduleType),
      })),
      digest: signing.expectedDigest,
      enableSignature,
    };
    const artifact = {
      version: "oaath.permission-decision/v1",
      kind: "approve",
      requestId: prepared.permission_request.requestId,
      requestHash: prepared.request_hash,
      decidedAt: Math.floor(Date.now() / 1000),
      approvedPolicy: prepared.approved_policy,
      capabilityHash: kernelPermissionCapabilityHash(
        parseKernelPermissionApproval(installApproval),
      ),
      installApproval,
    };
    const decided = await json(
      await post(
        `/portal/transactions/${id}/decision`,
        { outcome: "approved", ...selection, artifact: JSON.stringify(artifact) },
        cookie,
      ),
    );
    return decided.redirect;
  }
  return { address: account.address as Hex, signerId: signerId as string, approve };
}

describe.skipIf(!ENABLED)("automation service end to end", () => {
  let anvil: Anvil;
  let cluster: TestCluster;
  let bundler: Awaited<ReturnType<typeof startBundler>>;
  let relay: Awaited<ReturnType<typeof startRelay>>;
  const replicas: AutomationService[] = [];

  beforeAll(async () => {
    anvil = await startAnvil(CHAIN_ID);
    const stack = await deployKernelStack(anvil);
    // The canonical ECDSA root validator that portal-derived accounts bind.
    const validator = await stack.wallet.sendTransaction({
      account: stack.submitter,
      to: kernelDeployment({ chainId: CHAIN_ID }).create2Deployer,
      data: v33.ecdsaValidator.deploymentInput as Hex,
      gas: 10_000_000n,
    });
    await anvil.client.waitForTransactionReceipt({ hash: validator });
    bundler = await startBundler(anvil, stack);
    relay = await startRelay();
    cluster = await startCluster();
  }, 600_000);

  afterAll(async () => {
    for (const replica of replicas) await replica.close().catch(() => undefined);
    bundler?.close();
    relay?.process.kill("SIGTERM");
    cluster?.stop();
    anvil?.stop();
  });

  it("authorizes, activates on setup inclusion, and sends due slots before earlier operations finalize, never resending", async () => {
    const market = await deployMarket(anvil);
    const definition = dcaAutomation({
      chainId: CHAIN_ID,
      sellToken: market.sellToken,
      dca: market.dca,
      every: 60,
      grace: 55,
      maxOccurrences: 5,
    });
    const servicePort = await freePort();
    const publicUrl = `http://127.0.0.1:${servicePort}`;
    const client = await json(
      await fetch(`${relay.url}/oauth/clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          client_name: "Automation e2e",
          redirect_uris: [`${publicUrl}/v1/oauth/callback`],
        }),
      }),
    );
    const env = {
      DATABASE_URL: await cluster.database(),
      AUTOMATION_SEAL_KEY: randomBytes(32).toString("hex"),
      AUTOMATION_PUBLIC_URL: publicUrl,
      OAATH_ISSUER: relay.url,
      OAATH_CLIENT_ID: client.client_id,
      AUTOMATION_APPLICATIONS: `e2e:${createHash("sha256").update(APP_TOKEN).digest("hex")}`,
      [`AUTOMATION_RPC_URL_${CHAIN_ID}`]: anvil.url,
      [`AUTOMATION_BUNDLER_URL_${CHAIN_ID}`]: bundler.url,
    };
    // Two replicas over one database: either may claim any run.
    for (const listen of [`127.0.0.1:${servicePort}`, "127.0.0.1:0"])
      replicas.push(
        await startAutomationService(
          configFromEnv({ ...env, AUTOMATION_LISTEN: listen }, [definition]),
          {
            executors: 2,
          },
        ),
      );
    const [a] = replicas as [AutomationService, AutomationService];

    const root = await portalRoot(relay.url);
    await anvil.rpc("anvil_setBalance", [root.address, "0x8ac7230489e80000"]);
    await market.mint(root.address, 10_000_000n);

    const call = async (method: string, path: string, token: string, body?: unknown) =>
      json(
        await fetch(`${a.url}${path}`, {
          method,
          headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
          ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        }),
      );
    // The application's user is the root's OAAth signer: the service's
    // login_hint binds it and the account at the issuer.
    const session = await call("POST", "/v1/sessions", APP_TOKEN, {
      userId: root.signerId,
      account: root.address,
    });
    const startAt = Math.floor(Date.now() / 1000) + 45;
    const plan = await call("POST", "/v1/plans", session.token, {
      automation: "dca.v1",
      params: { budget: "2000000", maxSlippageBps: "500" },
      occurrences: 2,
      startAt,
      idempotencyKey: "e2e-plan",
    });
    const { authorizationUrl } = await call(
      "POST",
      `/v1/plans/${plan.id}/authorize`,
      session.token,
      {},
    );
    // Included operations stay short of finality until the end of the test.
    bundler.state.holdFinality = true;
    const redirect = await root.approve(authorizationUrl);
    const callback = await fetch(redirect, { redirect: "manual" });
    expect(await callback.text()).toBe("Authorization authorized. You can close this window.");
    expect((await call("GET", `/v1/plans/${plan.id}`, session.token)).status).toMatch(
      /authorized|active/u,
    );

    // Setup: deploy the account, enable the permission, approve and open the plan.
    // Its inclusion, not its finality, activates the plan.
    await until(
      async () => (await call("GET", `/v1/plans/${plan.id}`, session.token)).status === "active",
      "setup to be included",
      60,
    );
    expect(bundler.state.sends).toBe(1);
    const setupRun = async () =>
      (await call("GET", `/v1/plans/${plan.id}/runs`, session.token)).runs.find(
        (entry: { kind: string }) => entry.kind === "setup",
      );
    expect((await setupRun())?.status).toBe("observed");

    // The first occurrence's operation is accepted but held out of the chain.
    bundler.state.hold = true;
    const run = async (slot: number) =>
      (await call("GET", `/v1/plans/${plan.id}/runs`, session.token)).runs.find(
        (entry: { kind: string; slot: number }) =>
          entry.kind === "occurrence" && entry.slot === slot,
      );
    const submitted = await until(async () => {
      const current = await run(0);
      return current?.operation ? current : null;
    }, "the occurrence to be journaled and sent");
    await until(
      async () => (bundler.state.receiptReads.get(submitted.operation) ?? 0) >= 3,
      "repeated observation of the held operation",
    );
    expect(bundler.state.sends).toBe(2);
    // Slot 0 was sent on its own lane while setup was still included, not final.
    expect((await setupRun())?.status).toBe("observed");
    await bundler.release();
    await until(
      async () => (await run(0))?.status === "observed",
      "the occurrence to be observed included",
    );

    // The second slot comes due a minute later and is sent on time on its own lane.
    const second = await until(
      async () => {
        const current = await run(1);
        return current?.status === "observed" ? current : null;
      },
      "the second slot to be included while the first awaits finality",
      150,
    );
    expect((await run(0))?.status).toBe("observed");
    expect(bundler.state.sends).toBe(3);
    const nonces = await a.context.pool.query(
      "SELECT run_key, lane, op_nonce FROM automation_runs WHERE plan_id=$1 AND kind='occurrence' ORDER BY slot",
      [plan.id],
    );
    expect(
      nonces.rows.map((row) => [row.run_key, row.lane, (BigInt(row.op_nonce) >> 64n) & 0xffffn]),
    ).toEqual([
      ["occurrence:0", 1, 1n],
      ["occurrence:1", 2, 2n],
    ]);

    await bundler.finalize();
    const finalized = await Promise.all(
      [0, 1].map((slot) =>
        until(async () => {
          const current = await run(slot);
          return current?.status === "finalized" ? current : null;
        }, `slot ${slot} to finalize`),
      ),
    );
    await until(async () => (await setupRun())?.status === "finalized", "setup to finalize", 150);
    expect(finalized.map((entry) => entry.operation)).toEqual([
      submitted.operation,
      second.operation,
    ]);
    // One send per operation across both replicas and every observation pass.
    expect(bundler.state.sends).toBe(3);

    for (const [slot, entry] of finalized.entries()) {
      expect(entry.transactionHash).toMatch(/^0x[0-9a-f]{64}$/u);
      const receipt = await anvil.client.getTransactionReceipt({ hash: entry.transactionHash });
      const purchases = (receipt?.logs ?? []).flatMap((log) => {
        try {
          const event = decodeEventLog({
            abi: parseAbi([
              "event Purchased(bytes32 indexed planId, uint32 indexed slot, address indexed account, uint256 amountIn, uint256 amountOut)",
            ]),
            data: log.data,
            topics: log.topics as never,
          });
          return [event.args];
        } catch {
          return [];
        }
      });
      expect(purchases).toHaveLength(1);
      expect(purchases[0]).toMatchObject({ planId: plan.id, slot, amountIn: 1_000_000n });
      expect((purchases[0]?.amountOut ?? 0n) > 0n).toBe(true);
    }

    const leases = await a.context.pool.query(
      "SELECT run_key, status, generation, attempts FROM automation_runs WHERE plan_id=$1 ORDER BY run_key",
      [plan.id],
    );
    expect(
      leases.rows.filter((row) => row.status === "finalized").map((row) => row.run_key),
    ).toEqual(["occurrence:0", "occurrence:1", "setup"]);
    expect(leases.rows.every((row) => row.attempts === 0)).toBe(true);
  }, 600_000);
});
