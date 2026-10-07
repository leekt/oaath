import { createAutomation } from "@oaath/automation";
import { AutomationCreator } from "@oaath/automation/react";
import { createRoot } from "react-dom/client";

const response = await fetch("/api/session", { method: "POST" });
if (!response.ok) throw Error("session_unavailable");
const session = await response.json();
const client = createAutomation({
	baseUrl: `${location.origin}/api/automation`,
	token: session.token,
});
async function ownerAction(
	action: string,
	planId: string,
	commitment?: string,
) {
	const r = await fetch(`/demo/${action}`, {
		method: "POST",
		headers: {
			authorization: `Bearer ${session.token}`,
			"content-type": "application/json",
		},
		body: JSON.stringify({ planId, commitment }),
	});
	if (!r.ok) throw Error("owner_action_pending");
	return r.json();
}
const owner = {
	approve: (
		review: Parameters<typeof AutomationCreator>[0]["owner"] extends {
			approve: (r: infer R) => unknown;
		}
			? R
			: never,
	) => ownerAction("approve", review.terms.planId, review.commitment),
	cancel: (
		plan: Parameters<
			Parameters<typeof AutomationCreator>[0]["owner"]["cancel"]
		>[0],
	) => ownerAction("cancel", plan.id),
};
createRoot(document.getElementById("root")!).render(
	<>
		<header className="example-header">
			<a href="/" aria-label="Automation home">
				oaath<span> / automation</span>
			</a>
			<span className="example-environment">Local demonstration</span>
		</header>
		<main>
			<div className="example-notice">
				<strong>DCA example</strong>
				<span>
					Real execution on a local test chain. This demo uses a test owner
					wallet and test funds.
				</span>
			</div>
			<AutomationCreator client={client} owner={owner} />
		</main>
		<footer>
			Automation API + SDK <span>Built on OAAth · Cetane · Moesi</span>
		</footer>
	</>,
);
