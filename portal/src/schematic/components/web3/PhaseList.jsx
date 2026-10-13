/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import React from "react";
const labels = {
  complete: "Complete",
  current: "In progress",
  running: "Working",
  waiting: "Waiting",
  failed: "Failed",
};
export function PhaseList({ phases = [], className = "", ...props }) {
  return (
    <ol className={`ds-phases ${className}`} aria-live="polite" {...props}>
      {phases.map((phase, index) => (
        <li
          key={phase.id || index}
          data-phase={phase.id}
          data-status={phase.status}
          aria-current={phase.status === "current" ? "step" : undefined}
        >
          <span className="ds-phase-marker" aria-hidden="true">
            {phase.status === "complete"
              ? "✓"
              : phase.status === "failed"
                ? "!"
                : index + 1}
          </span>
          <span className="ds-phase-copy">
            <strong>{phase.title || phase.label}</strong>
            {(phase.detail || phase.description) && (
              <small>{phase.detail || phase.description}</small>
            )}
          </span>
          <span className="ds-phase-status">
            {phase.statusText || labels[phase.status] || labels.waiting}
          </span>
        </li>
      ))}
    </ol>
  );
}
