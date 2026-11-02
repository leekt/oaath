/**
 * One exact plain transaction an app asks the signer's own wallet to send:
 * a factory call with value, a contract creation, or an EntryPoint
 * `handleOps`. The portal shows every field, the wallet sends exactly it on
 * the request's chain, and the hash the wallet returns is the decision.
 * OAAth never sends; the relay releases the hash to the app once.
 *
 * @author taek <leekt216@gmail.com>
 */
import { type OwnerTransactionRequest, parseOwnerTransactionRequest } from "@oaath/protocol";
import { toHex } from "cetane/utils";
import { useEffect, useMemo, useRef, useState } from "react";
import { CHAINS, ether } from "./GrantReview.js";
import { Button as SchematicAction } from "./schematic/components";
import { findWallet } from "./session.js";
import { type RememberedSigner, shortAddress } from "./signers.js";

class TransactionError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

function failure(error: unknown): string {
  switch ((error as { code?: string | number })?.code) {
    case "request-invalid":
      return "This transaction request is malformed, so OAAth will not send it.";
    case "wrong-wallet":
      return "This transaction must be sent by another wallet. Sign in with the wallet it names.";
    case "wallet-account-mismatch":
      return "Switch your wallet to the address shown as the sender, then try again.";
    case "wallet-unavailable":
      return "Your wallet is not available in this browser. Open it and try again.";
    case "no-hash":
      return "Your wallet returned no transaction hash. Check your wallet before trying again.";
    case 4001:
      return "The transaction was rejected in your wallet.";
    case 4902:
      return "Your wallet doesn't know this network yet. Add it in your wallet, then try again.";
    default:
      return "Something went wrong. Check your wallet before trying again.";
  }
}

/** The exact request, sent by the wallet this signer is. */
function reviewed(relayed: unknown, signer: RememberedSigner): Readonly<OwnerTransactionRequest> {
  let request: Readonly<OwnerTransactionRequest>;
  try {
    request = parseOwnerTransactionRequest(relayed);
  } catch {
    throw new TransactionError("request-invalid");
  }
  if (signer.profile.kind !== "ecdsa" || signer.profile.address !== request.from)
    throw new TransactionError("wrong-wallet");
  return request;
}

/** Sends exactly `request` from the signer's wallet and answers its hash. */
async function send(request: Readonly<OwnerTransactionRequest>, signer: RememberedSigner) {
  let wallet: Awaited<ReturnType<typeof findWallet>>;
  try {
    wallet = await findWallet(signer.rdns);
  } catch {
    throw new TransactionError("wallet-unavailable");
  }
  const provider = wallet.provider;
  const accounts = await provider.request({ method: "eth_requestAccounts" });
  if (
    !Array.isArray(accounts) ||
    !accounts.some((entry) => entry?.toLowerCase?.() === request.from)
  )
    throw new TransactionError("wallet-account-mismatch");
  const chainId = toHex(request.chainId);
  await provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId }] });
  const hash = await provider.request({
    method: "eth_sendTransaction",
    params: [
      {
        from: request.from,
        ...(request.to === null ? {} : { to: request.to }),
        value: toHex(BigInt(request.value)),
        data: request.data,
        chainId,
      },
    ],
  });
  if (typeof hash !== "string" || !/^0x[0-9a-fA-F]{64}$/u.test(hash))
    throw new TransactionError("no-hash");
  return hash.toLowerCase();
}

export function TransactionReview({
  clientName,
  request: relayed,
  signer,
  onApproved,
  onCancel,
}: {
  clientName: string;
  request: unknown;
  signer: RememberedSigner;
  onApproved: (transactionHash: string) => void;
  onCancel: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const checked = useMemo(() => {
    try {
      return { request: reviewed(relayed, signer), error: null };
    } catch (cause) {
      return { request: null, error: failure(cause) };
    }
  }, [relayed, signer]);

  useEffect(() => heading.current?.focus(), []);

  async function approve() {
    if (!checked.request) return;
    setBusy(true);
    setError(null);
    try {
      onApproved(await send(checked.request, signer));
    } catch (cause) {
      setError(failure(cause));
      setBusy(false);
    }
  }

  const request = checked.request;
  const bytes = request ? (request.data.length - 2) / 2 : 0;
  return (
    <section aria-labelledby="transaction-heading">
      <h1 id="transaction-heading" ref={heading} tabIndex={-1}>
        Review and send transaction
      </h1>
      <p className="quiet">{clientName} asks your wallet to send this exact transaction itself.</p>
      {request && (
        <dl className="review">
          <dt>Chain</dt>
          <dd>{CHAINS[request.chainId] ?? `Chain ${request.chainId}`}</dd>
          <dt>From</dt>
          <dd className="mono">{request.from}</dd>
          <dt>To</dt>
          <dd className="mono">{request.to ?? "New contract (contract creation)"}</dd>
          <dt>Sends</dt>
          <dd>{ether(request.value)}</dd>
          <dt>Data</dt>
          <dd>
            {bytes === 0 ? (
              "None"
            ) : (
              <>
                {bytes} bytes, {request.to === null ? "init code" : "first 4 bytes"}{" "}
                <span className="mono" title={request.data}>
                  {shortAddress(request.data.slice(0, 10))}
                </span>
              </>
            )}
          </dd>
        </dl>
      )}
      {request && (
        <p className="notice">
          Approving asks your wallet to send this one transaction from {shortAddress(request.from)}{" "}
          and pay its gas. It can't be undone once sent.
        </p>
      )}
      <div className="actions">
        <SchematicAction
          type="button"
          variant="primary"
          className="primary"
          disabled={!request || busy}
          onClick={approve}
        >
          Send from my wallet
        </SchematicAction>
      </div>
      {(error ?? checked.error) && (
        <p className="error" role="alert">
          {error ?? checked.error}
        </p>
      )}
      <SchematicAction
        type="button"
        variant="ghost"
        className="cancel"
        disabled={busy}
        onClick={onCancel}
      >
        Cancel and return to the app
      </SchematicAction>
    </section>
  );
}
