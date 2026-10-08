import type { ApprovalJournal, ApprovalRecord } from "./approval.js";
/** IndexedDB transactions coordinate tabs; memory/localStorage are not submission journals. */
export function createBrowserJournal<T>(
	name = "automation-owner-v1",
	factory: IDBFactory = globalThis.indexedDB,
): {
	read(key: string): Promise<T | null>;
	compareAndSwap(key: string, expected: T | null, next: T): Promise<boolean>;
} {
	let database: Promise<IDBDatabase> | undefined;
	const open = () =>
		(database ??= new Promise((resolve, reject) => {
			if (!factory) return reject(Error("approval_storage_unavailable"));
			const request = factory.open(name, 1);
			request.onupgradeneeded = () =>
				request.result.createObjectStore("approvals");
			request.onsuccess = () => resolve(request.result);
			request.onerror = () => reject(Error("approval_storage_unavailable"));
		}));
	return {
		async read(key) {
			const db = await open();
			return new Promise((resolve, reject) => {
				const tx = db.transaction("approvals", "readonly");
				const r = tx.objectStore("approvals").get(key);
				tx.oncomplete = () => resolve((r.result as T | undefined) ?? null);
				tx.onabort = () => reject(Error("approval_storage_unavailable"));
			});
		},
		async compareAndSwap(key, expected, next) {
			const db = await open();
			return new Promise((resolve, reject) => {
				const tx = db.transaction("approvals", "readwrite", {
					durability: "strict",
				});
				const store = tx.objectStore("approvals");
				const r = store.get(key);
				let changed = false;
				r.onsuccess = () => {
					if (JSON.stringify(r.result ?? null) === JSON.stringify(expected)) {
						store.put(next, key);
						changed = true;
					}
				};
				tx.oncomplete = () => resolve(changed);
				tx.onabort = () => reject(Error("approval_storage_unavailable"));
			});
		},
	};
}

export const createApprovalJournal = (
	name?: string,
	factory?: IDBFactory,
): ApprovalJournal => createBrowserJournal<ApprovalRecord>(name, factory);
