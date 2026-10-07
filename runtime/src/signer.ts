import { OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION } from "@oaath/protocol";
import {
	createScopedSessionSigner,
	type RelaySessionSignerProvider,
	type SessionSignerIdentity,
	type SignerScope,
} from "@oaath/server";
import { createPostgresSignerStore } from "@oaath/server/postgres";
import { getRecord, insertRecord, open, plan, pool, seal } from "./store.js";

export const registry = createScopedSessionSigner({
	store: createPostgresSignerStore({ pool }),
	kms: {
		encrypt: async (value) =>
			JSON.stringify(seal(value, "automation.signer-registry/v1")),
		decrypt: async (value) =>
			open(JSON.parse(value), "automation.signer-registry/v1"),
	},
});
export function scopeFor(p: any): SignerScope {
	if (p.key_scope === "application")
		return { applicationId: p.app_id, scope: "application" };
	if (p.key_scope === "user" && p.user_id)
		return { applicationId: p.app_id, scope: "user", userId: p.user_id };
	throw Error("signer_scope_invalid");
}
async function bound(identity: Readonly<SessionSignerIdentity>) {
	const p = await plan(identity.deviceId);
	if (p.app_id !== identity.clientId || p.account !== identity.subject)
		throw Error("signer_identity_mismatch");
	return p;
}
/** Plan admission is local; OAAth owns the stable, sealed scope credential. */
export const signerProvider: RelaySessionSignerProvider = {
	async credential(identity) {
		const p = await bound(identity);
		let binding = await getRecord(p.id, "session");
		if (!binding) {
			if (
				p.status !== "draft" ||
				p.signer ||
				(await getRecord(p.id, "authorization"))
			)
				throw Error("custody_missing");
			const created = await registry.create(scopeFor(p));
			await insertRecord(p.id, "session", created);
			binding = await getRecord(p.id, "session");
		}
		const credential = await registry.recover(scopeFor(p), binding.address);
		if (
			credential.bindingId !== binding.bindingId ||
			credential.scope !== p.key_scope ||
			(p.signer && p.signer !== credential.address)
		)
			throw Error("signer_binding_mismatch");
		return {
			version: OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
			kind: "ecdsa",
			address: credential.address,
		};
	},
	async sign(request) {
		const p = await bound(request);
		if (p.status !== "active") throw Error("signing_admission_closed");
		const binding = await getRecord(p.id, "session");
		if (
			!binding ||
			binding.address !== p.signer ||
			binding.scope !== p.key_scope
		)
			throw Error("signer_binding_mismatch");
		return registry.sign(scopeFor(p), p.signer, request.hash);
	},
};
