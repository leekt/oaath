import {
	captureDcaTerms,
	DCA_TERMS_FIELDS,
	hashDcaTerms,
	hashPermissionRequest,
	OAATH_GRANT_POLICY_VERSION,
	OAATH_KERNEL_EXISTING_ACCOUNT_PROFILE_VERSION,
	OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
	OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
	OAATH_PERMISSION_DECISION_VERSION,
	OAATH_PERMISSION_REQUEST_VERSION,
	parseGrantPolicy,
	parsePermissionRequest,
} from "@oaath/protocol";
import {
	captureOaathBinding,
	deriveSessionPolicyProfiles,
	type OaathBindingInput,
} from "@oaath/sdk/advanced";
import { openHeadlessGrant } from "@oaath/sdk/headless";
import {
	kernelPermissionCapabilityHash as kernelGrantCapabilityHash,
	kernelKey,
	prepareExistingAccountPermissionApproval,
	readKernelPermissionStatus,
	sessionOperator,
	signedKernelPermissionApproval,
} from "@oaath/sdk/kernel";
import { hashTypedData, recoverTypedDataAddress } from "viem";
import {
	config,
	encode,
	executor,
	factory,
	ports,
	read,
	rpc,
	tokenAbi,
} from "./chain.js";
import { verifyDeployment } from "./deployment.js";
import { signerProvider } from "./signer.js";
import {
	getRecord,
	grants,
	insertRecord,
	now,
	operations,
	plan,
	pool,
} from "./store.js";

export const fees = {
	serviceFee: "0",
	payer: "account",
	maxFeePerGas: config.maxFeePerGas,
	maxGasCost: config.maxGasCost,
};
const signUnavailable = async (): Promise<never> => {
	throw new Error("owner_action_required");
};
export async function material(id: string, create = false) {
	const p = await plan(id);
	if (!create && !(await getRecord(id, "session")))
		throw new Error("custody_missing");
	const identity = { clientId: p.app_id, subject: p.account, deviceId: id };
	const credential = (await signerProvider.credential(identity)) as {
		address: `0x${string}`;
	};
	const account = {
		address: credential.address,
		sign: async ({ hash }: { hash: `0x${string}` }) =>
			(await signerProvider.sign({ ...identity, hash })) as `0x${string}`,
	};
	return {
		account,
		key: kernelKey({ account, validator: config.ecdsaValidator }),
	};
}
export async function authority(id: string) {
	const p = await plan(id),
		m = await material(id),
		ch = ports();
	const terms = captureDcaTerms(p.terms);
	const auth = await getRecord(id, "authorization");
	if (!auth) throw new Error("consent_missing");
	const ownerKey = kernelKey({
		account: { address: auth.owner, sign: signUnavailable },
		validator: config.ecdsaValidator,
	});
	const prepared = await prepareExistingAccountPermissionApproval({
		account: terms.account,
		owner: ownerKey,
		operator: sessionOperator({
			key: m.key,
			policies: deriveSessionPolicyProfiles(auth.request.policy),
		}),
		chains: [{ chainId: terms.chainId, reads: ch.reads }],
		requestHash: hashPermissionRequest(auth.request),
		kernelVersion: "0.4.0",
	});
	return { p, m, ch, terms, auth, ownerKey, prepared };
}
export async function authorize(id: string) {
	let p = await plan(id);
	const terms = captureDcaTerms(p.terms);
	if (
		p.fee_terms &&
		(p.fee_terms.maxFeePerGas !== config.maxFeePerGas ||
			p.fee_terms.maxGasCost !== config.maxGasCost)
	)
		throw new Error("runtime_profile_mismatch");
	if (!["draft", "awaiting_consent", "authorized"].includes(p.status))
		throw new Error("plan_state_conflict");
	const m = await material(id, true);
	const ch = ports();
	let auth = await getRecord(id, "authorization");
	if (!auth) {
		await verifyDeployment();
		const owner = String(
			await ch.reads.read({
				type: "kernel_ecdsa_owner",
				chainId: terms.chainId,
				account: terms.account,
			}),
		).toLowerCase();
		const values = DCA_TERMS_FIELDS.map(([k, t]) =>
			t.startsWith("uint") ? BigInt(terms[k]) : terms[k],
		);
		const predicted = String(
			await read(config.factory, factory.abi, "predict", [values]),
		).toLowerCase();
		const bindingInput: OaathBindingInput = {
			issuer: "https://dca.oaath.local",
			applicationId: p.app_id,
			applicationName: "Managed DCA",
			clientId: p.app_id,
			origin: "https://dca.oaath.local",
			redirectUri: "https://dca.oaath.local/callback",
			deviceId: id.slice(2),
			userHandle: p.account,
			context: {
				version: "oaath.workspace-account-context/v1",
				workspaceId: p.app_id,
				workspaceKind: "personal",
				accountId: p.account,
			},
			account: {
				version: OAATH_KERNEL_EXISTING_ACCOUNT_PROFILE_VERSION,
				kind: "kernel",
				kernelVersion: "0.4.0",
				address: terms.account,
				entryPoint: { version: "0.9" },
				ownerCredential: {
					version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
					kind: "ecdsa",
					address: owner,
				},
			},
			operatorCredential: {
				version: OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
				kind: "ecdsa",
				address: m.account.address.toLowerCase(),
			},
		};
		const binding = captureOaathBinding(bindingInput);
		const policy = parseGrantPolicy({
			version: OAATH_GRANT_POLICY_VERSION,
			calls: [
				{
					target: predicted,
					selector: encode(executor.abi, "execute", [0]).slice(0, 10),
					valueLimit: "0",
					argumentEquals: [],
				},
			],
			validAfter: terms.startAt,
			validUntil: terms.endAt - 1,
			perChainOperationLimit: { count: terms.maxRuns, intervalSeconds: null },
		});
		const request = parsePermissionRequest({
			version: OAATH_PERMISSION_REQUEST_VERSION,
			requestId: id,
			context: binding.context,
			application: binding.application,
			chainScope: "all",
			logicalAccount: binding.account,
			operatorCredential: binding.operatorCredential,
			policy,
			requestedAt: Number(p.created_at),
			expiresAt: terms.endAt,
			sessionSigner: {
				mode: "oaath_hosted",
				providerId: "dca-sealed-postgres-v1",
			},
		});
		const consent = {
			domain: {
				name: "OAAth DCA",
				version: "1",
				chainId: terms.chainId,
				verifyingContract: predicted,
			},
			types: {
				DcaConsent: [
					{ name: "termsHash", type: "bytes32" },
					{ name: "permissionHash", type: "bytes32" },
					{ name: "signer", type: "address" },
					{ name: "custody", type: "string" },
					{ name: "maxFeePerGas", type: "uint256" },
					{ name: "maxGasCost", type: "uint256" },
					{ name: "serviceFee", type: "uint256" },
				],
			},
			primaryType: "DcaConsent",
			message: {
				termsHash: hashDcaTerms(terms),
				permissionHash: hashPermissionRequest(request),
				signer: m.account.address.toLowerCase(),
				custody: "oaath_hosted",
				maxFeePerGas: config.maxFeePerGas,
				maxGasCost: config.maxGasCost,
				serviceFee: "0",
			},
		};
		auth = {
			owner,
			executor: predicted,
			bindingInput,
			request,
			consent,
			commitment: hashTypedData(consent as never),
			setupCalls: [
				{
					target: config.factory,
					data: encode(factory.abi, "create", [values]),
					value: "0",
				},
				{
					target: terms.sellToken,
					data: encode(tokenAbi, "approve", [
						predicted,
						BigInt(terms.totalInputCap),
					]),
					value: "0",
				},
			],
		};
		await insertRecord(id, "authorization", auth);
		auth = await getRecord(id, "authorization");
	}
	await pool.query(
		"UPDATE dca_plans SET status='awaiting_consent',revision=revision+1,executor=$2,signer=$3,commitment=$4,fee_terms=$5 WHERE id=$1 AND status='draft'",
		[id, auth.executor, m.account.address.toLowerCase(), auth.commitment, fees],
	);
	const a = await authority(id);
	p = await plan(id);
	if (!["awaiting_consent", "authorized"].includes(p.status))
		throw new Error("plan_state_conflict");
	return {
		status: "pending",
		plan: publicPlan(p),
		review: {
			commitment: auth.commitment,
			custody: "oaath_hosted",
			terms,
			fees,
			permission: a.prepared.typedData,
			consent: auth.consent,
			setupCalls: auth.setupCalls,
		},
	};
}
export function publicPlan(p: any) {
	return {
		id: p.id,
		status: p.status,
		terms: p.terms,
		commitment: p.commitment,
		executor: p.executor,
		signer: p.signer,
		fees,
	};
}
export async function verifySetup(p: any) {
	const terms = captureDcaTerms(p.terms);
	const block = await rpc("eth_getBlockByNumber", ["finalized", false]);
	if (!block?.hash) throw new Error("finality_unavailable");
	const pin = { blockHash: block.hash, requireCanonical: true };
	const h = await read(p.executor, executor.abi, "termsHash", [], pin);
	if (h !== hashDcaTerms(terms)) throw new Error("setup_commitment_mismatch");
	const allowance = await read(
		terms.sellToken,
		tokenAbi,
		"allowance",
		[terms.account, p.executor],
		pin,
	);
	const spent = await read(p.executor, executor.abi, "totalSpent", [], pin);
	if (
		allowance > BigInt(terms.totalInputCap) ||
		allowance < BigInt(terms.totalInputCap) - spent
	)
		throw new Error("allowance_mismatch");
	if (await read(p.executor, executor.abi, "cancelled", [], pin))
		throw new Error("executor_cancelled");
	const canonical = await rpc("eth_getBlockByNumber", [block.number, false]);
	if (canonical.hash !== block.hash) throw new Error("canonicality_unproven");
	return { blockNumber: block.number, blockHash: block.hash, termsHash: h };
}
export async function approve(id: string, input: any) {
	const a = await authority(id);
	if (!["awaiting_consent", "authorized"].includes(a.p.status))
		throw new Error("plan_state_conflict");
	if (
		input.commitment !== a.auth.commitment ||
		hashDcaTerms(a.terms) !== a.auth.consent.message.termsHash
	)
		throw new Error("consent_mismatch");
	const owner = await recoverTypedDataAddress({
		...a.auth.consent,
		signature: input.consentSignature,
	});
	if (owner.toLowerCase() !== a.auth.owner) throw new Error("consent_invalid");
	const approval = await signedKernelPermissionApproval({
		runtime: a.prepared.runtime,
		account: a.prepared.account,
		nonce: a.prepared.nonce,
		owner: a.auth.owner,
		typedData: a.prepared.typedData,
		signature: input.permissionSignature,
	});
	const decision = {
		version: OAATH_PERMISSION_DECISION_VERSION,
		kind: "approve",
		requestId: id,
		requestHash: hashPermissionRequest(a.auth.request),
		decidedAt: now(),
		approvedPolicy: a.auth.request.policy,
		capabilityHash: kernelGrantCapabilityHash(approval),
	};
	await insertRecord(id, "decision", {
		decision,
		approval,
		consentSignature: input.consentSignature,
		commitment: a.auth.commitment,
	});
	return activate(id);
}
export async function activate(id: string) {
	const p = await plan(id),
		auth = await getRecord(id, "authorization"),
		decision = await getRecord(id, "decision");
	if (!["awaiting_consent", "authorized"].includes(p.status))
		return {
			status: p.status === "active" ? "active" : "pending",
			plan: publicPlan(p),
		};
	if (
		!auth ||
		!decision ||
		decision.commitment !== p.commitment ||
		hashDcaTerms(p.terms) !== auth.consent.message.termsHash
	)
		throw new Error("activation_forbidden");
	assertRuntime(p, auth);
	await material(id);
	try {
		const deployment = await verifyDeployment();
		const setup = { ...(await verifySetup(p)), deployment };
		await verifyGrantAuthority(id);
		await pool.query(
			"UPDATE dca_plans SET status='authorized',revision=revision+1,setup=$2,diagnostic=NULL WHERE id=$1 AND status='awaiting_consent' AND commitment=$3",
			[id, setup, auth.commitment],
		);
		if ((await plan(id)).status !== "authorized")
			throw new Error("activation_forbidden");
		const grant = await openGrant(id);
		await grant.close();
		await pool.query(
			"UPDATE dca_plans SET status='active',revision=revision+1 WHERE id=$1 AND status='authorized' AND commitment=$2 AND (terms->>'endAt')::bigint>$3",
			[id, auth.commitment, now()],
		);
	} catch {
		await pool.query(
			"UPDATE dca_plans SET diagnostic='setup_confirmation_pending' WHERE id=$1 AND status IN ('awaiting_consent','authorized')",
			[id],
		);
	}
	const current = await plan(id);
	return {
		status: current.status === "active" ? "active" : "pending",
		plan: publicPlan(current),
	};
}
export async function activationWorker(signal: AbortSignal) {
	while (!signal.aborted) {
		const row = await pool.query(
			"UPDATE dca_plans SET next_setup_at=$1 WHERE id=(SELECT p.id FROM dca_plans p WHERE status IN ('awaiting_consent','authorized') AND next_setup_at<=$2 AND EXISTS(SELECT 1 FROM dca_runtime_records r WHERE r.plan_id=p.id AND r.kind='decision') ORDER BY next_setup_at LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING id",
			[now() + 60, now()],
		);
		if (row.rows[0]) {
			try {
				await activate(row.rows[0].id);
			} catch {
				await pool.query(
					"UPDATE dca_plans SET diagnostic='activation_evidence_unavailable' WHERE id=$1",
					[row.rows[0].id],
				);
			}
		} else await new Promise((resolve) => setTimeout(resolve, 1000));
	}
}
function assertRuntime(p: any, auth: any) {
	for (const name of [
		"chainId",
		"sellToken",
		"buyToken",
		"router",
		"poolFee",
		"sellFeed",
		"buyFeed",
		"maxPriceAgeSeconds",
	]) {
		if (p.terms[name] !== config[name])
			throw new Error("runtime_profile_mismatch");
	}
	if (
		auth.consent.message.maxFeePerGas !== config.maxFeePerGas ||
		auth.consent.message.maxGasCost !== config.maxGasCost ||
		auth.consent.message.custody !== "oaath_hosted" ||
		auth.consent.message.serviceFee !== "0"
	)
		throw new Error("runtime_profile_mismatch");
}
export async function openGrant(
	id: string,
): Promise<Readonly<import("@oaath/sdk").OaathGrantHandle>> {
	const p = await plan(id),
		auth = await getRecord(id, "authorization"),
		decision = await getRecord(id, "decision"),
		m = await material(id);
	if (
		!auth ||
		!decision ||
		decision.commitment !== p.commitment ||
		hashDcaTerms(p.terms) !== auth.consent.message.termsHash ||
		m.account.address.toLowerCase() !== p.signer
	)
		throw new Error("authority_mismatch");
	assertRuntime(p, auth);
	const ch = ports();
	const guarded = {
		...ch,
		quote: async (request: any) => {
			const quote: any = await ch.quote(request);
			const g = quote.gas;
			if (
				g &&
				(BigInt(g.maxFeePerGas) > BigInt(config.maxFeePerGas) ||
					(BigInt(g.callGasLimit) +
						BigInt(g.verificationGasLimit) +
						BigInt(g.preVerificationGas)) *
						BigInt(g.maxFeePerGas) >
						BigInt(config.maxGasCost))
			)
				throw new Error("fee_ceiling_exceeded");
			return quote;
		},
		submission: {
			open: async (request: any) => {
				const latest = await plan(id);
				if (latest.status !== "active") throw new Error("admission_closed");
				return ch.submission.open(request);
			},
		},
	};
	return openHeadlessGrant({
		binding: auth.bindingInput,
		request: auth.request,
		decision: decision.decision,
		installApproval: decision.approval,
		grants,
		operations,
		chains: new Map([[config.chainId, guarded]]),
		ownerKey: kernelKey({
			account: { address: auth.owner, sign: signUnavailable },
			validator: config.ecdsaValidator,
		}),
		sessionKey: m.key,
		invalidation: {
			invalidateCapability: async ({ grantId, capabilityHash }) => {
				const latest = await plan(id);
				if (grantId !== id || latest.status !== "cancelling")
					throw new Error("invalidation_forbidden");
				return { evidenceHash: latest.commitment, invalidatedAt: now() };
			},
		},
		ownerRevocations: { request: async () => {} },
		now,
	});
}
async function verifyGrantAuthority(id: string) {
	const decision = await getRecord(id, "decision");
	if (!decision) throw new Error("consent_missing");
	const status = await readKernelPermissionStatus({
		approval: decision.approval,
		chainId: config.chainId,
		reads: ports().reads,
		blockTag: "finalized",
	});
	if (!["installed", "approval-replayable"].includes(status.status))
		throw new Error("grant_authority_unavailable");
}
export async function resume(id: string) {
	const p = await plan(id);
	if (p.status !== "paused" || p.terms.endAt <= now())
		throw new Error("resume_forbidden");
	await verifySetup(p);
	await verifyGrantAuthority(id);
	const g = await openGrant(id);
	const active = g.state === "active";
	await g.close();
	if (!active) throw new Error("grant_inactive");
	await pool.query(
		"UPDATE dca_plans SET status='active',revision=revision+1 WHERE id=$1 AND status='paused' AND revision=$2",
		[id, p.revision],
	);
	return { status: (await plan(id)).status };
}
