/** A popup returns a public link pointer, never a session or approval artifact. */
export interface MembershipContext {
  origin: string;
  state: string;
  account: `0x${string}`;
  label: string;
}

export function membershipContext(hash: string): MembershipContext | null {
  const params = new URLSearchParams(hash.replace(/^#/u, ""));
  try {
    const origin = params.get("return_origin") ?? "";
    const url = new URL(origin);
    if (
      url.origin !== origin ||
      (url.protocol !== "https:" &&
        !(url.protocol === "http:" && ["localhost", "127.0.0.1"].includes(url.hostname)))
    )
      return null;
    const state = params.get("state") ?? "";
    const account = params.get("account") ?? "";
    const label = (params.get("label") ?? "").trim();
    if (
      !/^[A-Za-z0-9_-]{43}$/u.test(state) ||
      !/^0x[0-9a-fA-F]{40}$/u.test(account) ||
      !label ||
      label.length > 64
    )
      return null;
    return { origin, state, account: account as `0x${string}`, label };
  } catch {
    return null;
  }
}

export function matchingMembership(context: MembershipContext, link: { address: string }) {
  return context.account.toLowerCase() === link.address.toLowerCase();
}

export function returnMembership(
  context: MembershipContext,
  link: {
    link_id: string;
    address: string;
    label: string;
    status: string;
  },
) {
  if (!matchingMembership(context, link) || !window.opener || window.opener.closed)
    throw new Error("The app window is closed. Return to the invite and open OAAth again.");
  window.opener.postMessage(
    {
      type: "oaath.membership-handoff/v1",
      state: context.state,
      linkId: link.link_id,
      account: link.address,
      label: link.label,
      status: link.status,
    },
    context.origin,
  );
  window.close();
}
