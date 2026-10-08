/**
 * An account's policy templates, for its owner: named spending limits a
 * signer can be given when it is added or later. A template is configuration
 * only; nothing happens on-chain until the owner signs a grant from it.
 *
 * @author taek <leekt216@gmail.com>
 */
import { useState } from "react";
import { type PolicyTemplate, type PolicyTemplateInput, portalApi } from "./api.js";
import { message } from "./shared.js";

const DAY = 86_400;

/** One line a person can read: what a template allows, and for how long. */
export function templateSummary(template: PolicyTemplate): string {
  const limit = template.policy.perChainOperationLimit;
  const operations = `${limit.count} operation${limit.count === 1 ? "" : "s"} per chain${
    limit.intervalSeconds === null
      ? ""
      : limit.intervalSeconds === DAY
        ? " a day"
        : ` every ${limit.intervalSeconds} s`
  }`;
  const calls = template.policy.calls.length;
  const days = template.lifetime_seconds / DAY;
  const lifetime = Number.isInteger(days)
    ? `${days} day${days === 1 ? "" : "s"}`
    : `${template.lifetime_seconds} s`;
  return `${calls} call${calls === 1 ? "" : "s"} · ${operations} · ${lifetime}`;
}

interface Draft {
  readonly name: string;
  readonly days: string;
  readonly count: string;
  readonly daily: boolean;
  readonly calls: readonly { target: string; selector: string; valueLimit: string }[];
}

const EMPTY: Draft = {
  name: "",
  days: "30",
  count: "10",
  daily: true,
  calls: [{ target: "", selector: "0xa9059cbb", valueLimit: "0" }],
};

function draftOf(template: PolicyTemplate): Draft {
  const limit = template.policy.perChainOperationLimit;
  return {
    name: template.name,
    days: String(template.lifetime_seconds / DAY),
    count: String(limit.count),
    daily: limit.intervalSeconds !== null,
    calls: template.policy.calls.map((call) => ({ ...call })),
  };
}

/** The relay validates fully; this only shapes the form into the wire body. */
function inputOf(draft: Draft): PolicyTemplateInput {
  return {
    name: draft.name.trim(),
    lifetime_seconds: Math.round(Number(draft.days) * DAY),
    policy: {
      calls: draft.calls.map((call) => ({
        target: call.target.trim() as `0x${string}`,
        selector: call.selector.trim() as `0x${string}`,
        valueLimit: call.valueLimit.trim(),
      })),
      perChainOperationLimit: {
        count: Number(draft.count),
        intervalSeconds: draft.daily ? DAY : null,
      },
    },
  };
}

export function Policies({
  accountId,
  templates,
  onChange,
}: {
  accountId: string;
  templates: readonly PolicyTemplate[];
  onChange: (templates: readonly PolicyTemplate[]) => void;
}) {
  const [editing, setEditing] = useState<{ id: string | null; draft: Draft } | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run(work: () => Promise<readonly PolicyTemplate[]>) {
    setBusy(true);
    setError(null);
    try {
      onChange(await work());
      setEditing(null);
      setDeleting(null);
    } catch (failure) {
      setError(
        (failure as { code?: string })?.code === "relay_request_invalid"
          ? "OAAth can't enforce that policy. Check each address, selector and limit."
          : message(failure),
      );
    }
    setBusy(false);
  }

  function save(event: React.FormEvent) {
    event.preventDefault();
    if (!editing) return;
    const body = inputOf(editing.draft);
    const id = editing.id;
    return run(async () => {
      if (id === null) return [...templates, await portalApi.createPolicy(accountId, body)];
      const saved = await portalApi.updatePolicy(accountId, id, body);
      return templates.map((template) => (template.template_id === id ? saved : template));
    });
  }

  const set = (patch: Partial<Draft>) =>
    setEditing((current) => current && { ...current, draft: { ...current.draft, ...patch } });

  return (
    <section aria-labelledby="policies-heading" className="members">
      <h2 id="policies-heading">Policies</h2>
      <p className="quiet">
        Spending limits you can give a signer. Changing one never changes a signer's existing
        access.
      </p>
      {templates.length === 0 && <p className="quiet">No policies yet.</p>}
      <ul className="choices">
        {templates.map((template) => (
          <li key={template.template_id}>
            <div className="choice member">
              <span className="choice-text">
                <span className="choice-title">{template.name}</span>
                <span className="choice-detail">{templateSummary(template)}</span>
              </span>
              <div className="member-actions">
                {deleting === template.template_id ? (
                  <button
                    type="button"
                    className="danger"
                    disabled={busy}
                    onClick={() =>
                      run(async () => {
                        await portalApi.deletePolicy(accountId, template.template_id);
                        return templates.filter(
                          (entry) => entry.template_id !== template.template_id,
                        );
                      })
                    }
                  >
                    Confirm delete
                  </button>
                ) : (
                  <>
                    <button
                      type="button"
                      className="secondary"
                      disabled={busy}
                      aria-label={`Edit ${template.name}`}
                      onClick={() =>
                        setEditing({ id: template.template_id, draft: draftOf(template) })
                      }
                    >
                      Edit
                    </button>
                    <button
                      type="button"
                      className="secondary"
                      disabled={busy}
                      aria-label={`Delete ${template.name}`}
                      onClick={() => setDeleting(template.template_id)}
                    >
                      Delete
                    </button>
                  </>
                )}
              </div>
            </div>
          </li>
        ))}
      </ul>
      {!editing && (
        <button
          type="button"
          className="secondary"
          disabled={busy}
          onClick={() => setEditing({ id: null, draft: EMPTY })}
        >
          New policy
        </button>
      )}
      {editing && (
        <form className="link-request policy-editor" onSubmit={save} aria-label="Policy">
          <label>
            Name
            <input
              id="policy-name"
              required
              maxLength={64}
              value={editing.draft.name}
              onChange={(event) => set({ name: event.target.value })}
            />
          </label>
          {editing.draft.calls.map((call, index) => (
            <fieldset className="access" key={`call-${index.toString()}`}>
              <legend>Allowed call {index + 1}</legend>
              <label>
                Contract
                <input
                  className="mono policy-target"
                  required
                  pattern="0x[0-9a-fA-F]{40}"
                  spellCheck={false}
                  value={call.target}
                  onChange={(event) =>
                    set({
                      calls: editing.draft.calls.map((entry, at) =>
                        at === index ? { ...entry, target: event.target.value } : entry,
                      ),
                    })
                  }
                />
              </label>
              <label>
                Function selector
                <input
                  className="mono"
                  required
                  pattern="0x[0-9a-fA-F]{8}"
                  spellCheck={false}
                  value={call.selector}
                  onChange={(event) =>
                    set({
                      calls: editing.draft.calls.map((entry, at) =>
                        at === index ? { ...entry, selector: event.target.value } : entry,
                      ),
                    })
                  }
                />
              </label>
              <label>
                Value limit (wei)
                <input
                  className="mono"
                  required
                  inputMode="numeric"
                  pattern="[0-9]+"
                  value={call.valueLimit}
                  onChange={(event) =>
                    set({
                      calls: editing.draft.calls.map((entry, at) =>
                        at === index ? { ...entry, valueLimit: event.target.value } : entry,
                      ),
                    })
                  }
                />
              </label>
              {editing.draft.calls.length > 1 && (
                <button
                  type="button"
                  className="link"
                  onClick={() =>
                    set({ calls: editing.draft.calls.filter((_, at) => at !== index) })
                  }
                >
                  Remove this call
                </button>
              )}
            </fieldset>
          ))}
          <button
            type="button"
            className="link"
            onClick={() => set({ calls: [...editing.draft.calls, { ...EMPTY.calls[0]! }] })}
          >
            Add another call
          </button>
          <label>
            Operations per chain
            <input
              id="policy-count"
              required
              inputMode="numeric"
              pattern="[0-9]+"
              value={editing.draft.count}
              onChange={(event) => set({ count: event.target.value })}
            />
          </label>
          <label className="inline">
            <input
              type="checkbox"
              checked={editing.draft.daily}
              onChange={(event) => set({ daily: event.target.checked })}
            />
            Reset every day
          </label>
          <label>
            Valid for (days)
            <input
              id="policy-days"
              required
              inputMode="decimal"
              value={editing.draft.days}
              onChange={(event) => set({ days: event.target.value })}
            />
          </label>
          <div className="actions">
            <button type="submit" className="primary" disabled={busy}>
              Save policy
            </button>
            <button type="button" className="link" disabled={busy} onClick={() => setEditing(null)}>
              Cancel
            </button>
          </div>
        </form>
      )}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
    </section>
  );
}
