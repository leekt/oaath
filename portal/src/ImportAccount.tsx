/**
 * "Import an existing account": checks that the signed-in signer is the root of
 * a deployed Kernel v4 account on Arbitrum Sepolia and lists every installed
 * module. Reading signs and saves nothing; the import itself is submitted later.
 *
 * @author taek <leekt216@gmail.com>
 */
import { type FormEvent, useState } from "react";
import {
  type AccountInspection,
  IMPORT_NETWORK,
  type InventoryModule,
  inspectAccount,
  type ModuleOrigin,
} from "./account-import.js";
import { type RememberedSigner, shortAddress } from "./signers.js";

const STATUS_MARK = { pass: "✓", fail: "✕", unknown: "?" } as const;
const STATUS_TEXT = { pass: "Passed", fail: "Failed", unknown: "Not readable" } as const;
const ORIGIN_TEXT: Readonly<Record<ModuleOrigin, string>> = {
  root: "Root",
  oaath: "OAAth",
  outside: "Outside OAAth",
};
const MODULE_KIND: Readonly<Record<number, string>> = {
  1: "Validator",
  2: "Executor",
  3: "Fallback handler",
  5: "Policy",
  6: "Signer",
  11: "Execution hook",
};

function ModuleRow({ module }: { module: InventoryModule }) {
  return (
    <li className={`module module-${module.origin}`}>
      <span className="choice-text">
        <span className="choice-title">
          {module.label}
          {module.count > 1 ? ` ×${module.count}` : ""}
        </span>
        <span className="choice-detail">
          {MODULE_KIND[module.moduleType] ?? "Module"} ·{" "}
          <span className="mono" title={module.module}>
            {shortAddress(module.module)}
          </span>
          {module.evidence === "history" ? " · install history only" : ""}
        </span>
      </span>
      <span className={`origin origin-${module.origin}`}>{ORIGIN_TEXT[module.origin]}</span>
    </li>
  );
}

export function ImportAccount({ signer }: { signer: RememberedSigner }) {
  const [address, setAddress] = useState("");
  const [busy, setBusy] = useState(false);
  const [inspection, setInspection] = useState<AccountInspection | null>(null);

  async function check(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setInspection(null);
    try {
      setInspection(
        await inspectAccount({
          address,
          signer: signer.profile,
          rpcUrl: `${location.origin}/rpc/421614`,
        }),
      );
    } finally {
      setBusy(false);
    }
  }

  const inventory = inspection?.inventory ?? null;
  return (
    <section id="import-account" className="import" aria-labelledby="import-heading">
      <h2 id="import-heading">Import an existing account</h2>
      <p className="quiet">
        A Kernel v4 account on {IMPORT_NETWORK} whose root is {signer.label}. Checking reads the
        account; nothing is signed or saved.
      </p>
      <form onSubmit={check}>
        <label htmlFor="import-address">Account address</label>
        <input
          id="import-address"
          className="mono"
          value={address}
          onChange={(event) => setAddress(event.target.value)}
          placeholder="0x…"
          autoComplete="off"
          spellCheck={false}
          disabled={busy}
          required
        />
        <button type="submit" className="secondary" disabled={busy || address.trim() === ""}>
          Check account
        </button>
      </form>
      {busy && (
        <p className="quiet" aria-live="polite">
          Reading the account on {IMPORT_NETWORK}…
        </p>
      )}
      {inspection && (
        <ol className="checks" aria-label="Account checks">
          {inspection.checks.map((check) => (
            <li key={check.id} className={`check check-${check.status}`}>
              <span className="check-mark" aria-hidden="true">
                {STATUS_MARK[check.status]}
              </span>
              <span className="choice-text">
                <span className="choice-title">
                  {check.label}
                  <span className="visually-hidden"> {STATUS_TEXT[check.status]}</span>
                </span>
                <span className="choice-detail">{check.detail}</span>
              </span>
            </li>
          ))}
        </ol>
      )}
      {inspection?.inventoryError && (
        <p className="error" role="alert">
          {inspection.inventoryError}
        </p>
      )}
      {inventory && (
        <div className="inventory" data-fingerprint={inventory.fingerprint}>
          <h3>Installed modules</h3>
          <p className={inventory.outside > 0 ? "warning" : "quiet"}>
            {inventory.outside === 0
              ? "No modules outside OAAth."
              : `${inventory.outside} ${inventory.outside === 1 ? "module" : "modules"} outside OAAth. They keep their authority over this account; importing will ask you to acknowledge them.`}
          </p>
          {!inventory.complete && (
            <p className="warning">Not every module could be confirmed. {inventory.note ?? ""}</p>
          )}
          <ul className="modules">
            {inventory.modules.map((module) => (
              <ModuleRow
                key={`${module.moduleType}:${module.module}:${module.origin}`}
                module={module}
              />
            ))}
          </ul>
          <p className="quiet">
            Read at block {inventory.blockNumber}. Fingerprint{" "}
            <span className="mono" title={inventory.fingerprint}>
              {shortAddress(inventory.fingerprint)}
            </span>
          </p>
        </div>
      )}
    </section>
  );
}
