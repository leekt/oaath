/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import React from "react";
export const Checkbox = React.forwardRef(function Checkbox(
  {
    label,
    hint,
    onChange,
    onCheckedChange,
    className = "",
    id: suppliedId,
    "aria-describedby": describedBy,
    ...props
  },
  ref,
) {
  const generatedId = React.useId();
  const id = suppliedId || generatedId;
  return (
    <label className={`ds-check ${className}`} htmlFor={id}>
      <input
        ref={ref}
        id={id}
        aria-labelledby={label != null ? `${id}-label` : undefined}
        type="checkbox"
        aria-describedby={
          [describedBy, hint && `${id}-hint`].filter(Boolean).join(" ") ||
          undefined
        }
        onChange={(event) => {
          onChange?.(event.target.checked);
          onCheckedChange?.(event.target.checked);
        }}
        {...props}
      />
      <span>
        <span id={`${id}-label`} className="ds-check-label">
          {label}
        </span>
        {hint && (
          <span id={`${id}-hint`} className="ds-field-note">
            {hint}
          </span>
        )}
      </span>
    </label>
  );
});
