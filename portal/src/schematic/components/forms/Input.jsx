/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import React from "react";
import { FormField, fieldDescription } from "./FormField.jsx";
export const Input = React.forwardRef(function Input(
  {
    label,
    hint,
    error,
    prefix,
    suffix,
    mono,
    dense,
    className = "",
    id: suppliedId,
    "aria-describedby": describedBy,
    "aria-invalid": invalid,
    ...props
  },
  ref,
) {
  const generatedId = React.useId();
  const id = suppliedId || generatedId;
  const input = (
    <input
      data-ds-autofocus={props.autoFocus || undefined}
      ref={ref}
      id={id}
      className={`ds-input${mono ? " ds-mono" : ""}${dense ? " ds-input--dense" : ""} ${className}`}
      aria-invalid={error ? true : invalid}
      aria-describedby={fieldDescription(id, describedBy, hint, error)}
      {...props}
    />
  );
  const control =
    prefix || suffix ? (
      <div className="ds-input-group">
        {prefix && <span className="ds-input-affix">{prefix}</span>}
        {input}
        {suffix && <span className="ds-input-affix">{suffix}</span>}
      </div>
    ) : (
      input
    );
  return label != null || hint || error ? (
    <FormField
      id={id}
      label={label}
      hint={hint}
      error={error}
      required={props.required}
    >
      {control}
    </FormField>
  ) : (
    control
  );
});
