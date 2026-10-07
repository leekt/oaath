import { OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION } from "@oaath/protocol";
import type {
	RelaySessionSignerProvider,
	SessionSignerIdentity,
} from "@oaath/server";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { getRecord, insertRecord, plan } from "./store.js";

async function bound(identity: Readonly<SessionSignerIdentity>) {
	const p = await plan(identity.deviceId);
	if (p.app_id !== identity.clientId || p.account !== identity.subject)
		throw Error("signer_identity_mismatch");
	return p;
}
/** Durable deployment of OAAth's existing hosted signer port; never exports a private scalar. */
export const signerProvider: RelaySessionSignerProvider = {
	async credential(identity) {
		const p = await bound(identity);
		let record = await getRecord(p.id, "session");
		if (!record) {
			if (
				p.status !== "draft" ||
				p.signer ||
				(await getRecord(p.id, "authorization"))
			)
				throw Error("custody_missing");
			await insertRecord(p.id, "session", { privateKey: generatePrivateKey() });
			record = await getRecord(p.id, "session");
		}
		return {
			version: OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
			kind: "ecdsa",
			address: privateKeyToAccount(record.privateKey).address.toLowerCase(),
		};
	},
	async sign(request) {
		if (!/^0x[0-9a-f]{64}$/.test(request.hash))
			throw Error("signer_hash_invalid");
		const p = await bound(request);
		if (p.status !== "active") throw Error("signing_admission_closed");
		const record = await getRecord(p.id, "session");
		if (!record) throw Error("custody_missing");
		const account = privateKeyToAccount(record.privateKey);
		if (account.address.toLowerCase() !== p.signer)
			throw Error("signer_binding_mismatch");
		return account.sign({ hash: request.hash });
	},
};
