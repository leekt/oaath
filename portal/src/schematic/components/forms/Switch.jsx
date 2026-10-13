/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import React from "react";
export const Switch = React.forwardRef(function Switch(
  {
    label,
    hint,
    checked = false,
    onChange,
    onCheckedChange,
    className = "",
    id: suppliedId,
    "aria-describedby": describedBy,
    disabled,
    ...props
  },
  ref,
) {
  const generatedId = React.useId();
  const id = suppliedId || generatedId;
  return (
    <div className={`ds-check ${className}`}>
      <button
        ref={ref}
        id={id}
        aria-labelledby={label != null ? `${id}-label` : undefined}
        type="button"
        role="switch"
        aria-checked={checked}
        aria-describedby={
          [describedBy, hint && `${id}-hint`].filter(Boolean).join(" ") ||
          undefined
        }
        disabled={disabled}
        className="ds-switch"
        onClick={() => {
          onChange?.(!checked);
          onCheckedChange?.(!checked);
        }}
        {...props}
      >
        <span className="ds-switch-track">
          <span />
        </span>
      </button>
      {(label || hint) && (
        <label htmlFor={id}>
          <span id={`${id}-label`} className="ds-check-label">
            {label}
          </span>
          {hint && (
            <span id={`${id}-hint`} className="ds-field-note">
              {hint}
            </span>
          )}
        </label>
      )}
    </div>
  );
});
