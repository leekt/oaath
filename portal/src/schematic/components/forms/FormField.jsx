/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import React from "react";
/** Use the same id on the field control; hints and errors are referenced through describedBy. */
export function FormField({
  id,
  label,
  hint,
  error,
  required,
  children,
  className = "",
  ...props
}) {
  return (
    <div className={`ds-field ${className}`} {...props}>
      {label != null && (
        <label className="ds-label" htmlFor={id}>
          {label}
          {required && (
            <span className="ds-field-required" aria-hidden="true">
              {" "}
              (required)
            </span>
          )}
        </label>
      )}
      {children}
      {(error || hint) && (
        <p
          className={`ds-field-note${error ? " ds-field-error" : ""}`}
          id={id ? `${id}-note` : undefined}
        >
          {error || hint}
        </p>
      )}
    </div>
  );
}
export function fieldDescription(id, describedBy, hint, error) {
  return (
    [describedBy, (hint || error) && `${id}-note`].filter(Boolean).join(" ") ||
    undefined
  );
}
