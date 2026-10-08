import { createAutomation } from "@oaath/automation";
import { createBrowserJournal } from "@oaath/automation/journal";
import { AutomationCreator } from "@oaath/automation/react";
import {
	createWalletOwner,
	type WalletProvider,
} from "@oaath/automation/wallet";
import { createCetaneChainPorts } from "@oaath/sdk/cetane";
import { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { Button } from "../../../sdk/src/ui/button.js";

type Provider = WalletProvider & {
	on?(name: string, listener: () => void): void;
	removeListener?(name: string, listener: () => void): void;
};
type Session = {
	owner: string;
	account: string;
	expiresAt: number;
	deployment: { factory: string; data: string };
	chains: Record<number, { publicRpcUrls: string[]; bundlerUrl: string }>;
};
type Balance = {
	deployed: boolean;
	eth: string;
	usdc: string;
	sellToken: string;
};
const provider = (window as Window & { ethereum?: Provider }).ethereum;
type SetupIntent = {
	status: "wallet_requested" | "submitted" | "declined";
	hash?: string;
};
const setupJournal = createBrowserJournal<SetupIntent>("dca-account-setup-v1");
async function api(path: string, body?: unknown) {
	const r = await fetch(
		`/api/${path}`,
		body === undefined
			? {}
			: {
					method: "POST",
					headers: { "content-type": "application/json" },
					body: JSON.stringify(body),
				},
	);
	const value = await r.json();
	if (!r.ok) throw Error(value.error ?? "service_unavailable");
	return value;
}
const format = (value: string, decimals: number) =>
	(Number(BigInt(value)) / 10 ** decimals).toLocaleString(undefined, {
		maximumFractionDigits: decimals === 18 ? 6 : 2,
	});
function App() {
	const heading = useRef<HTMLHeadingElement>(null);
	const focusTransition = useRef(false);
	const [setupIntent, setSetupIntent] = useState<
		SetupIntent | null | undefined
	>();
	const [session, setSession] = useState<Session | null>(null),
		[balance, setBalance] = useState<Balance | null>(null);
	const [busy, setBusy] = useState(false),
		[error, setError] = useState(""),
		[ready, setReady] = useState(false);
	const [connected, setConnected] = useState<{
		client: ReturnType<typeof createAutomation>;
		owner: ReturnType<typeof createWalletOwner>;
	} | null>(null);
	useEffect(() => {
		if (!session) {
			setSetupIntent(undefined);
			return;
		}
		let live = true;
		void setupJournal
			.read(session.account)
			.then((value) => {
				if (live) setSetupIntent(value);
			})
			.catch(() => {
				if (live)
					setError(
						"Browser storage is unavailable. Enable it before setting up an account.",
					);
			});
		return () => {
			live = false;
		};
	}, [session]);
	useEffect(() => {
		if (!focusTransition.current || (session && (!balance || !connected)))
			return;
		focusTransition.current = false;
		if (session && balance?.deployed)
			document.querySelector<HTMLElement>(".automation h1")?.focus();
		else heading.current?.focus();
	}, [session, balance, connected]);
	useEffect(() => {
		void api("session")
			.then(setSession)
			.catch(() => {})
			.finally(() => setReady(true));
		const changed = () => {
			setSession(null);
			setBalance(null);
			void api("logout", {}).catch(() => {});
		};
		provider?.on?.("accountsChanged", changed);
		provider?.on?.("chainChanged", changed);
		return () => {
			provider?.removeListener?.("accountsChanged", changed);
			provider?.removeListener?.("chainChanged", changed);
		};
	}, []);
	useEffect(() => {
		if (!session || !provider) {
			setConnected(null);
			return;
		}
		const chains = createCetaneChainPorts(session.chains, {
			maxRequests: 500,
			maxConcurrency: 4,
			retry: { attempts: 2, delayMs: 200 },
			timeoutMs: 12000,
			fetch: async (request) => {
				if (new URL(request.url).origin !== location.origin)
					throw Error("rpc_origin_denied");
				return fetch(request, { credentials: "same-origin" });
			},
		});
		const owner = createWalletOwner({ provider, chains });
		setConnected({
			client: createAutomation({
				baseUrl: `${location.origin}/api/automation`,
				token: "cookie",
			}),
			owner,
		});
		void api("account")
			.then(setBalance)
			.catch(() =>
				setError(
					"Could not read your account. Use Refresh account to try again.",
				),
			);
		return () => {
			void owner.close();
		};
	}, [session]);
	async function action(fn: () => Promise<void>) {
		setBusy(true);
		setError("");
		try {
			await fn();
		} catch (e) {
			const code = (e as { code?: number }).code;
			setError(
				code === 4001
					? "Wallet request declined. You can try again when ready."
					: e instanceof Error && e.message === "wallet_missing"
						? "Open this page in a wallet browser, or enable a browser wallet such as MetaMask or Rabby."
						: "The request could not finish. Check your wallet and testnet connection, then refresh the account. A pending transaction will not be sent again automatically.",
			);
		} finally {
			setBusy(false);
		}
	}
	async function connect() {
		if (!provider) throw Error("wallet_missing");
		const accounts = (await provider.request({
			method: "eth_requestAccounts",
		})) as string[];
		try {
			await provider.request({
				method: "wallet_switchEthereumChain",
				params: [{ chainId: "0x66eee" }],
			});
		} catch (e) {
			if ((e as { code?: number }).code !== 4902) throw e;
			await provider.request({
				method: "wallet_addEthereumChain",
				params: [
					{
						chainId: "0x66eee",
						chainName: "Arbitrum Sepolia",
						nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
						rpcUrls: ["https://sepolia-rollup.arbitrum.io/rpc"],
						blockExplorerUrls: ["https://sepolia.arbiscan.io"],
					},
				],
			});
		}
		const owner = accounts[0]!;
		const challenge = await api("login/challenge", { owner });
		const hex = `0x${Array.from(new TextEncoder().encode(challenge.message), (b) => b.toString(16).padStart(2, "0")).join("")}`;
		const signature = await provider.request({
			method: "personal_sign",
			params: [hex, owner],
		});
		const authenticated = await api("login/complete", {
			nonce: challenge.nonce,
			signature,
		});
		focusTransition.current = true;
		setSession(authenticated);
	}
	async function setup() {
		if (!provider || !session) return;
		const current = (await api("account")) as Balance;
		setBalance(current);
		if (current.deployed) return;
		const key = session.account;
		const previous = await setupJournal.read(key);
		if (previous && previous.status !== "declined") {
			setSetupIntent(previous);
			return;
		}
		const accounts = (await provider.request({
			method: "eth_accounts",
		})) as string[];
		if (
			accounts[0]?.toLowerCase() !== session.owner ||
			(await provider.request({ method: "eth_chainId" })) !== "0x66eee"
		)
			throw Error("wallet_changed");
		const requested: SetupIntent = { status: "wallet_requested" };
		if (!(await setupJournal.compareAndSwap(key, previous, requested))) {
			setSetupIntent(await setupJournal.read(key));
			return;
		}
		setSetupIntent(requested);
		try {
			const hash = await provider.request({
				method: "eth_sendTransaction",
				params: [
					{
						from: session.owner,
						to: session.deployment.factory,
						data: session.deployment.data,
						value: "0x0",
					},
				],
			});
			if (typeof hash !== "string" || !/^0x[\da-f]{64}$/i.test(hash))
				throw Error("wallet_reply_unresolved");
			const submitted: SetupIntent = { status: "submitted", hash };
			await setupJournal.compareAndSwap(key, requested, submitted);
			setSetupIntent(await setupJournal.read(key));
		} catch (e) {
			if ((e as { code?: number }).code === 4001) {
				await setupJournal.compareAndSwap(key, requested, {
					status: "declined",
				});
				setSetupIntent(await setupJournal.read(key));
			}
			throw e;
		}
		setBalance(await api("account"));
	}
	return (
		<>
			<header className="example-header">
				<a href="/" aria-label="Automation home">
					oaath<span> / automation</span>
				</a>
				<span className="example-environment">Arbitrum Sepolia · Testnet</span>
			</header>
			<main>
				<div className="example-notice">
					<strong>DCA example</strong>
					<span>
						Recurring USDC → WETH purchases. Connect your wallet and use test
						funds only.
					</span>
				</div>
				<section
					className="automation wallet-workspace"
					aria-label="Wallet and account"
				>
					{!session ? (
						<div className="automation-columns">
							<div>
								<h1 ref={heading} tabIndex={-1}>
									Your purchase, on a schedule.
								</h1>
								<p>
									Choose an amount, review the limits, and authorize recurring
									purchases from your smart account.
								</p>
								<p>
									Your wallet approves the plan. The service carries out
									eligible purchases and keeps their history.
								</p>
								<Button
									disabled={busy || !ready}
									onClick={() => void action(connect)}
								>
									{busy
										? "Check your wallet…"
										: !ready
											? "Opening workspace…"
											: "Connect wallet"}
								</Button>
								<p className="wallet-hint">
									Connecting asks for a login signature. Spending requires a
									separate review and approval.
								</p>
							</div>
							<aside className="automation-statement">
								<h2>Before you start</h2>
								<dl>
									<div>
										<dt>Network</dt>
										<dd>Arbitrum Sepolia</dd>
									</div>
									<div>
										<dt>Purchase</dt>
										<dd>USDC → WETH, once daily</dd>
									</div>
									<div>
										<dt>Funds</dt>
										<dd>Test USDC for purchases · test ETH for gas</dd>
									</div>
									<div>
										<dt>Missed purchases</dt>
										<dd>Skipped, never caught up</dd>
									</div>
								</dl>
							</aside>
						</div>
					) : (
						<>
							<div className="automation-heading">
								<div>
									{balance?.deployed ? (
										<h2>Your testnet account</h2>
									) : (
										<h1 className="wallet-title" ref={heading} tabIndex={-1}>
											Your testnet account
										</h1>
									)}
									<p>
										{balance
											? `${format(balance.eth, 18)} ETH for gas · ${format(balance.usdc, 6)} USDC available`
											: "Reading account balances…"}
									</p>
								</div>
								<Button
									variant="outline"
									disabled={busy}
									onClick={() =>
										void action(async () => {
											await api("logout", {});
											focusTransition.current = true;
											setSession(null);
											setBalance(null);
										})
									}
								>
									Disconnect
								</Button>
							</div>
							<details>
								<summary>Account address and funding</summary>
								<p>
									Send Arbitrum Sepolia test ETH and test USDC to this smart
									account. Its address differs from your connected wallet.
								</p>
								<code className="wallet-address">{session.account}</code>
								<p>
									<a
										href={`https://sepolia.arbiscan.io/address/${session.account}`}
										target="_blank"
										rel="noreferrer"
									>
										View account on Arbiscan
									</a>{" "}
									·{" "}
									<a
										href="https://faucet.circle.com"
										target="_blank"
										rel="noreferrer"
									>
										Get test USDC
									</a>
								</p>
							</details>
							{balance && !balance.deployed && (
								<div className="wallet-setup">
									<h3>Set up your smart account</h3>
									<p>
										This one-time wallet transaction creates your account. Your
										connected wallet pays the setup gas in test ETH. Plan
										approval and its bounded token allowance come next.
									</p>
									{setupIntent && setupIntent.status !== "declined" ? (
										<div role="status">
											<p>
												Account setup requested. Refresh the account to check
												confirmation.
											</p>
											{setupIntent.hash && (
												<a
													href={`https://sepolia.arbiscan.io/tx/${setupIntent.hash}`}
													target="_blank"
													rel="noreferrer"
												>
													View setup transaction
												</a>
											)}
										</div>
									) : (
										<Button
											disabled={busy || setupIntent === undefined}
											onClick={() => void action(setup)}
										>
											{busy ? "Check your wallet…" : "Set up account"}
										</Button>
									)}
								</div>
							)}
							<Button
								variant="outline"
								disabled={busy}
								onClick={() =>
									void action(async () => setBalance(await api("account")))
								}
							>
								Refresh account
							</Button>
							{balance?.deployed &&
								(BigInt(balance.eth) === 0n || BigInt(balance.usdc) === 0n) && (
									<p className="wallet-hint">
										Fund this account with test ETH for gas and test USDC for
										purchases before approving a plan.
									</p>
								)}
						</>
					)}
					{error && (
						<p role="alert" className="automation-error">
							{error}
						</p>
					)}
				</section>
				{session && connected && balance?.deployed && (
					<AutomationCreator
						client={connected.client}
						owner={connected.owner}
					/>
				)}
			</main>
			<footer>
				Automation API + SDK <span>Built on OAAth · Cetane · Moesi</span>
			</footer>
		</>
	);
}
createRoot(document.getElementById("root")!).render(<App />);
