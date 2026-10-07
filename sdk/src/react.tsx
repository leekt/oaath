"use client";
import {
	ArrowLeft,
	ArrowRight,
	Check,
	ChevronDown,
	Pause,
	Play,
	RefreshCw,
} from "lucide-react";
import { useEffect, useId, useRef, useState } from "react";
import type {
	Approval,
	AutomationClient,
	Config,
	CreatePlan,
	Plan,
	Run,
} from "./index.js";
import {
	AlertDialog,
	AlertDialogAction,
	AlertDialogCancel,
	AlertDialogContent,
	AlertDialogDescription,
	AlertDialogFooter,
	AlertDialogHeader,
	AlertDialogTitle,
	AlertDialogTrigger,
} from "./ui/alert-dialog.js";
import { Button } from "./ui/button.js";
import { Input } from "./ui/input.js";
import { Label } from "./ui/label.js";
import {
	Select,
	SelectContent,
	SelectItem,
	SelectTrigger,
	SelectValue,
} from "./ui/select.js";
export interface AutomationOwner {
	approve(review: NonNullable<Approval["review"]>): Promise<unknown>;
	cancel(plan: Plan): Promise<unknown>;
}
export interface AutomationCreatorProps {
	client: AutomationClient;
	owner: AutomationOwner;
	onChange?: (plan: Plan) => void;
}
const date = (n: number) =>
	new Date(n * 1000).toLocaleString(undefined, {
		dateStyle: "medium",
		timeStyle: "short",
	});
export function units(value: string, decimals = 6) {
	const n = BigInt(value),
		base = 10n ** BigInt(decimals);
	const fraction = (n % base)
		.toString()
		.padStart(decimals, "0")
		.replace(/0+$/, "");
	return `${n / base}${fraction ? `.${fraction}` : ""}`;
}
const scope = (value: string) =>
	value === "user"
		? "One session key for your user"
		: "One shared session key for this application";
const status = (value: string) =>
	({
		awaiting_consent: "Awaiting approval",
		authorized: "Confirming setup",
		active: "Active",
		paused: "Paused",
		cancelling: "Cancellation pending",
		cancelled: "Cancelled",
		completed: "Completed",
		expired: "Ended",
		draft: "Draft",
	})[value] ?? value;
const errorText = (e: unknown) => {
	const code = (e as { code?: string })?.code;
	if ((e as { status?: number })?.status === 422)
		return "Check the amount and schedule. Use a positive amount with at most six decimal places and 1–365 opportunities, then review again.";
	if (code === "session_expired_or_invalid")
		return "Your session expired. Reopen this page to sign in again.";
	if (code === "request_outcome_unknown")
		return "The reply was lost. The outcome is being checked; retrying uses the same saved request.";
	if (code === "wallet_chain_mismatch")
		return "Switch your wallet to the account’s chain, then try again.";
	return "This action could not be completed. Your saved automation is retained. Try again or refresh its status.";
};
function Details({
	plan,
	review,
}: {
	plan: Plan;
	review?: NonNullable<Approval["review"]>;
}) {
	const t = plan.terms;
	return (
		<details className="automation-details">
			<summary>
				Account, price source & onchain terms <ChevronDown size={16} />
			</summary>
			<dl>
				{Object.entries({
					"Account / recipient": t.account,
					"Chain ID": t.chainId,
					"Sell token": t.sellToken,
					"Buy token": t.buyToken,
					"Swap router": t.router,
					"Pool fee": `${t.poolFee / 10000}%`,
					"Sell price feed": t.sellFeed,
					"Buy price feed": t.buyFeed,
					"Maximum price age": `${t.maxPriceAgeSeconds} seconds`,
					Executor: plan.executor,
					"Session signer": plan.signer,
					Commitment: plan.commitment,
					"Plan ID": plan.id,
				}).map(([k, v]) => (
					<div key={k}>
						<dt>{k}</dt>
						<dd>{String(v ?? "Pending")}</dd>
					</div>
				))}
			</dl>
			<p>
				Each swap verifies both feed prices and their freshness onchain. Minimum
				output uses their ratio minus the approved tolerance. Only standard
				tokens on this fixed route are supported.
			</p>
			{review && (
				<>
					<h4>Owner setup transactions</h4>
					<p>
						Create this executor and approve at most {units(t.totalInputCap)}{" "}
						USDC for it. Both calls below require your wallet. Purchases return
						to your account.
					</p>
					<pre>{JSON.stringify(review.setupCalls, null, 2)}</pre>
					<h4>Signed authorization</h4>
					<pre>
						{JSON.stringify(
							{ consent: review.consent, permission: review.permission },
							null,
							2,
						)}
					</pre>
				</>
			)}
		</details>
	);
}
function Statement({ plan, config }: { plan: Plan; config: Config }) {
	const t = plan.terms;
	return (
		<>
			<p className="automation-statement">
				Spend up to{" "}
				<strong>
					{units(t.amountIn)} {config.sell.symbol}
				</strong>{" "}
				buying <strong>{config.buy.symbol}</strong> every day.
			</p>
			<dl className="automation-totals">
				<div>
					<dt>Maximum input spend</dt>
					<dd>
						{units(t.totalInputCap)} {config.sell.symbol}
					</dd>
				</div>
				<div>
					<dt>Scheduled opportunities</dt>
					<dd>{t.maxRuns}</dd>
				</div>
				<div>
					<dt>Price tolerance</dt>
					<dd>{t.maxSlippageBps / 100}%</dd>
				</div>
				<div>
					<dt>Starts</dt>
					<dd>{date(t.startAt)}</dd>
				</div>
				<div>
					<dt>Ends</dt>
					<dd>{date(t.endAt)}</dd>
				</div>
			</dl>
			<p>
				Each opportunity stays open for {t.graceSeconds / 60} minutes. Missed or
				failed purchases are skipped; {t.maxRuns} successful purchases are not
				guaranteed.
			</p>
			<div className="automation-fees">
				<h3>Fees & signing</h3>
				<p>
					Service fee: {plan.fees.serviceFee}. Gas is paid separately by your
					account, up to {units(plan.fees.maxGasCost, 18)} native tokens per
					purchase and {units(plan.fees.maxFeePerGas, 9)} gwei per gas. Setup
					and cancellation also require gas.
				</p>
				<p>
					{scope(plan.keyScope)}. OAAth holds the session key; your wallet
					retains owner authority.
				</p>
			</div>
		</>
	);
}
/** One supplied end-user flow. Projection polling never initiates chain observation. */
export function AutomationCreator({
	client,
	owner,
	onChange,
}: AutomationCreatorProps) {
	const id = useId();
	const [config, setConfig] = useState<Config>();
	const [plans, setPlans] = useState<Plan[]>([]);
	const [selected, setSelected] = useState<Plan>();
	const [review, setReview] = useState<NonNullable<Approval["review"]>>();
	const [runs, setRuns] = useState<Run[]>([]);
	const [amount, setAmount] = useState("25"),
		[opportunities, setOpportunities] = useState("30"),
		[slippage, setSlippage] = useState("50");
	const [busy, setBusy] = useState(false),
		[error, setError] = useState(""),
		[notice, setNotice] = useState("");
	const [unknownCreate, setUnknownCreate] = useState(false);
	const intent = useRef<CreatePlan | undefined>(undefined);
	const epoch = useRef(0);
	const heading = useRef<HTMLHeadingElement>(null);

	const viewKey = `${selected?.id ?? "create"}:${review?.commitment ?? "status"}`;
	const previousView = useRef(viewKey);
	useEffect(() => {
		if (previousView.current !== viewKey) {
			heading.current?.focus();
			previousView.current = viewKey;
		}
	}, [viewKey]);
	async function load() {
		const [c, p] = await Promise.all([client.config(), client.list()]);
		setConfig(c);
		setPlans(p.plans);
		return c;
	}
	useEffect(() => {
		let live = true;
		Promise.all([client.config(), client.list()])
			.then(([c, p]) => {
				if (!live) return;
				setConfig(c);
				setPlans(p.plans);
				try {
					const saved = sessionStorage.getItem(
						`automation.create:${c.account}`,
					);
					if (saved) {
						intent.current = JSON.parse(saved);
						setUnknownCreate(true);
						setAmount(intent.current!.amount);
						setOpportunities(String(intent.current!.opportunities));
						setSlippage(String(intent.current!.maxSlippageBps));
					}
				} catch {
					setError(
						"Browser storage is unavailable. Enable it before creating an automation.",
					);
				}
			})
			.catch((e) => live && setError(errorText(e)));
		return () => {
			live = false;
			epoch.current++;
		};
	}, [client]);
	useEffect(() => {
		if (
			!selected ||
			!["active", "authorized", "awaiting_consent", "cancelling"].includes(
				selected.status,
			)
		)
			return;
		const timer = setInterval(() => {
			if (document.visibilityState !== "visible") return;
			client
				.get(selected.id)
				.then((p) =>
					setSelected((current) => (current?.id === p.id ? p : current)),
				)
				.catch(() => {});
		}, 5000);
		return () => clearInterval(timer);
	}, [client, selected]);
	async function act(fn: () => Promise<void>) {
		if (busy) return;
		setBusy(true);
		setError("");
		setNotice("");
		try {
			await fn();
		} catch (e) {
			setError(errorText(e));
		} finally {
			setBusy(false);
		}
	}
	async function select(p: Plan) {
		const generation = ++epoch.current;
		setSelected(p);
		setReview(undefined);
		setRuns([]);
		const history = await client.listRuns(p.id);
		if (epoch.current === generation) setRuns(history.runs);
	}
	async function refresh() {
		if (!selected) return;
		const p = await client.get(selected.id);
		setSelected(p);
		setRuns((await client.listRuns(p.id)).runs);
		await load();
		onChange?.(p);
	}
	async function create() {
		if (!config) return;
		if (!intent.current) {
			const random = crypto.getRandomValues(new Uint8Array(16));
			intent.current = {
				recipe: "dca.v1",
				amount,
				opportunities: Number(opportunities),
				maxSlippageBps: Number(slippage),
				idempotencyKey: Array.from(random, (b) =>
					b.toString(16).padStart(2, "0"),
				).join(""),
			};
			sessionStorage.setItem(
				`automation.create:${config.account}`,
				JSON.stringify(intent.current),
			);
		}
		setUnknownCreate(true);
		let p: Plan;
		try {
			p = await client.create(intent.current);
		} catch (e) {
			const status = (e as { status?: number }).status;
			if (status && [400, 401, 403, 404, 409, 422].includes(status)) {
				sessionStorage.removeItem(`automation.create:${config.account}`);
				intent.current = undefined;
				setUnknownCreate(false);
			}
			throw e;
		}
		sessionStorage.removeItem(`automation.create:${config.account}`);
		intent.current = undefined;
		setUnknownCreate(false);
		setSelected(p);
		const authorized = await client.authorize(p.id);
		setSelected(authorized.plan);
		setReview(authorized.review);
		await load();
		onChange?.(p);
	}
	const total =
		/^\d+(\.\d{1,6})?$/.test(amount) && /^[1-9][0-9]{0,2}$/.test(opportunities)
			? units(
					BigInt(
						amount
							.replace(".", "")
							.padEnd(
								amount.includes(".")
									? amount.length - 1 + (6 - amount.split(".")[1]!.length)
									: amount.length + 6,
								"0",
							),
					) *
						BigInt(opportunities) +
						"",
				)
			: "—";
	return (
		<section className="automation" aria-label="Automation creator">
			<div className="automation-heading">
				<div>
					<h1 ref={heading} tabIndex={-1}>
						{selected
							? review
								? "Review your automation"
								: "Your automation"
							: "Make a purchase routine."}
					</h1>
					<p>
						{selected
							? "Your instruction, its authority, and every scheduled opportunity."
							: "Choose your amount. Set your limit. Approve once."}
					</p>
				</div>
				{selected && (
					<Button
						variant="ghost"
						disabled={busy}
						onClick={() => {
							epoch.current++;
							setSelected(undefined);
							setReview(undefined);
							setError("");
						}}
					>
						<ArrowLeft /> All automations
					</Button>
				)}
			</div>
			{error && (
				<p role="alert" className="automation-error">
					{error}
				</p>
			)}
			{notice && (
				<p role="status" className="automation-notice">
					{notice}
				</p>
			)}
			{!config ? (
				<p role="status">Loading your account…</p>
			) : selected ? (
				<>
					<div
						className="automation-columns automation-review-enter"
						key={viewKey}
					>
						<div className="automation-main">
							<div className="automation-title-row">
								<h2>Daily {config.buy.symbol} purchase</h2>
								<span
									className="automation-status"
									data-status={selected.status}
								>
									{status(selected.status)}
								</span>
							</div>
							<Statement plan={selected} config={config} />
							<Details plan={selected} review={review} />
						</div>
						<aside className="automation-aside">
							<h2>{review ? "Owner approval" : "Manage this instruction"}</h2>
							{review ? (
								<>
									<p>
										Approve the exact terms on this page. Your wallet will sign
										the consent and scoped permission, then submit the two setup
										calls.
									</p>
									<Button
										disabled={busy}
										onClick={() =>
											act(async () => {
												const evidence = await owner.approve(review);
												const a = await client.submitApproval(
													selected.id,
													evidence,
												);
												setSelected(a.plan);
												setReview(undefined);
												setNotice(
													a.status === "active"
														? "Your automation is active."
														: "Approval retained. Setup confirmation is pending; status will update automatically.",
												);
												await load();
											})
										}
									>
										{busy ? "Waiting for approval…" : "Approve with wallet"}
										<ArrowRight />
									</Button>
								</>
							) : (
								<>
									<p>
										Pause stops new scheduling. Cancellation also needs owner
										transactions to stop the executor, clear its allowance and
										revoke permission. Submitted work may finish first.
									</p>
									<div className="automation-actions">
										{["draft", "awaiting_consent", "authorized"].includes(
											selected.status,
										) && (
											<Button
												disabled={busy}
												onClick={() =>
													act(async () =>
														setReview(
															(await client.authorize(selected.id)).review,
														),
													)
												}
											>
												Review & approve
												<ArrowRight />
											</Button>
										)}
										{selected.status === "active" && (
											<Button
												variant="outline"
												disabled={busy}
												onClick={() =>
													act(async () => {
														setSelected(await client.pause(selected.id));
														await load();
													})
												}
											>
												<Pause />
												Pause
											</Button>
										)}
										{selected.status === "paused" && (
											<Button
												disabled={busy}
												onClick={() =>
													act(async () => {
														setSelected(await client.resume(selected.id));
														await load();
													})
												}
											>
												<Play />
												Resume
											</Button>
										)}
										{selected.status !== "cancelled" && (
											<AlertDialog>
												<AlertDialogTrigger asChild>
													<Button variant="outline" disabled={busy}>
														Cancel automation
													</Button>
												</AlertDialogTrigger>
												<AlertDialogContent className="automation">
													<AlertDialogHeader>
														<AlertDialogTitle>
															Cancel this automation?
														</AlertDialogTitle>
														<AlertDialogDescription>
															Scheduling stops immediately. Your wallet may need
															to confirm onchain cancellation. Purchases already
															submitted can still complete.
														</AlertDialogDescription>
													</AlertDialogHeader>
													<AlertDialogFooter>
														<AlertDialogCancel>
															Keep automation
														</AlertDialogCancel>
														<AlertDialogAction
															onClick={() =>
																act(async () => {
																	const p = await client.cancel(selected.id);
																	setSelected(p);
																	if (
																		p.cancellation?.status ===
																		"owner_action_required"
																	) {
																		await owner.cancel(p);
																		setNotice(
																			"Cancellation submitted. Its onchain effects are being confirmed.",
																		);
																	}
																	await refresh();
																})
															}
														>
															Stop & cancel
														</AlertDialogAction>
													</AlertDialogFooter>
												</AlertDialogContent>
											</AlertDialog>
										)}
										<Button
											variant="ghost"
											disabled={busy}
											onClick={() => act(refresh)}
										>
											<RefreshCw />
											Refresh status
										</Button>
									</div>
								</>
							)}
							{selected.status === "cancelled" && (
								<p className="automation-notice">
									<Check size={16} /> Onchain cancellation confirmed.
								</p>
							)}
						</aside>
					</div>
					<section className="automation-activity">
						<div className="automation-title-row">
							<h2>Execution history</h2>
							<Button
								variant="ghost"
								disabled={busy}
								onClick={() => act(refresh)}
							>
								<RefreshCw />
								Refresh
							</Button>
						</div>
						{runs.length === 0 ? (
							<p>No scheduled opportunity has been recorded yet.</p>
						) : (
							<div className="automation-table-wrap">
								<table>
									<thead>
										<tr>
											<th>Opportunity</th>
											<th>Scheduled time</th>
											<th>Result</th>
											<th>Details</th>
										</tr>
									</thead>
									<tbody>
										{runs.map((r) => (
											<tr key={r.slot}>
												<td>{r.slot + 1}</td>
												<td>{date(r.scheduled_at)}</td>
												<td>{r.status}</td>
												<td>
													{r.reason ??
														(r.status === "succeeded"
															? "Finalized purchase"
															: "—")}
												</td>
											</tr>
										))}
									</tbody>
								</table>
								{runs.length >= 50 && (
									<Button
										variant="ghost"
										disabled={busy}
										onClick={() =>
											act(async () => {
												const page = await client.listRuns(selected.id, {
													after: runs.at(-1)!.slot,
												});
												setRuns([...runs, ...page.runs]);
											})
										}
									>
										Load more
									</Button>
								)}
							</div>
						)}
					</section>
				</>
			) : (
				<>
					<div className="automation-columns">
						<form
							className="automation-main"
							onSubmit={(e) => {
								e.preventDefault();
								void act(create);
							}}
						>
							<h2>Recurring purchase</h2>
							<p>
								Buy {config.buy.symbol} with {config.sell.symbol}, once a day.
							</p>
							<fieldset
								disabled={busy || unknownCreate}
								className="automation-fields"
							>
								<div>
									<Label htmlFor={`${id}-amount`}>Amount each day</Label>
									<div className="automation-input-unit">
										<Input
											id={`${id}-amount`}
											inputMode="decimal"
											pattern="[0-9]+(\.[0-9]{1,6})?"
											required
											value={amount}
											onChange={(e) => setAmount(e.target.value)}
										/>
										<span>{config.sell.symbol}</span>
									</div>
								</div>
								<div className="automation-field-pair">
									<div>
										<Label htmlFor={`${id}-days`}>
											Scheduled opportunities
										</Label>
										<Input
											id={`${id}-days`}
											type="number"
											min="1"
											max="365"
											step="1"
											required
											value={opportunities}
											onChange={(e) => setOpportunities(e.target.value)}
										/>
									</div>
									<div>
										<Label htmlFor={`${id}-slippage`}>Price tolerance</Label>
										<Select value={slippage} onValueChange={setSlippage}>
											<SelectTrigger id={`${id}-slippage`}>
												<SelectValue />
											</SelectTrigger>
											<SelectContent>
												<SelectItem value="25">0.25%</SelectItem>
												<SelectItem value="50">0.50%</SelectItem>
												<SelectItem value="100">1.00%</SelectItem>
											</SelectContent>
										</Select>
									</div>
								</div>
							</fieldset>
							<p className="automation-help">
								The first opportunity starts about five minutes after creation.
								Review the exact times before approving.
							</p>
							<Button type="submit" disabled={busy || !config.account}>
								{busy
									? "Preparing your review…"
									: unknownCreate
										? "Retry saved creation"
										: "Review automation"}
								<ArrowRight />
							</Button>
							<p className="automation-help">
								Your funds stay in your account until a purchase.
							</p>
						</form>
						<aside className="automation-aside">
							<h2>Your purchase statement</h2>
							<p className="automation-statement">
								Buy <strong>{config.buy.symbol}</strong>
								<br />
								with{" "}
								<strong>
									{amount || "—"} {config.sell.symbol}
								</strong>{" "}
								every day.
							</p>
							<dl className="automation-totals">
								<div>
									<dt>Maximum input spend</dt>
									<dd>
										{total} {config.sell.symbol}
									</dd>
								</div>
								<div>
									<dt>Opportunities</dt>
									<dd>{opportunities || "—"}</dd>
								</div>
								<div>
									<dt>Network</dt>
									<dd>
										{config.chainId === 31337
											? "Local test chain"
											: `Chain ${config.chainId}`}
									</dd>
								</div>
							</dl>
							<p>
								Missed and failed opportunities are skipped. Gas and any service
								fees are separate.
							</p>
							<p>
								{scope(config.keyScope)}. Each automation receives its own
								permission.
							</p>
						</aside>
					</div>
					<section className="automation-activity">
						<h2>
							Your automations{" "}
							<span className="automation-count">{plans.length}</span>
						</h2>
						{plans.length === 0 ? (
							<div className="automation-empty">
								<p>Your first routine starts here.</p>
								<p>
									After approval, its schedule and purchase history will appear
									here.
								</p>
							</div>
						) : (
							<ul className="automation-plan-list">
								{plans.map((p) => (
									<li key={p.id}>
										<button
											type="button"
											disabled={busy}
											onClick={() => act(() => select(p))}
										>
											<span>
												<strong>
													{units(p.terms.amountIn)} {config.sell.symbol} →{" "}
													{config.buy.symbol}
												</strong>
												<small>
													Daily · {p.terms.maxRuns} opportunities ·{" "}
													{date(p.terms.startAt)}
												</small>
											</span>
											<span
												className="automation-status"
												data-status={p.status}
											>
												{status(p.status)}
											</span>
											<ArrowRight size={18} />
										</button>
									</li>
								))}
							</ul>
						)}
					</section>
				</>
			)}
		</section>
	);
}
