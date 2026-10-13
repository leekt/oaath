/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import React from "react";
export const Radio = React.forwardRef(function Radio(
  {
    label,
    hint,
    onChange,
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
        type="radio"
        aria-describedby={
          [describedBy, hint && `${id}-hint`].filter(Boolean).join(" ") ||
          undefined
        }
        onChange={(event) => onChange?.(event.target.value)}
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
