/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import React from "react";
import { FormField, fieldDescription } from "./FormField.jsx";
export const Textarea = React.forwardRef(function Textarea(
  {
    label,
    hint,
    error,
    mono,
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
  const control = (
    <textarea
      data-ds-autofocus={props.autoFocus || undefined}
      ref={ref}
      id={id}
      className={`ds-input ds-textarea${mono ? " ds-mono" : ""} ${className}`}
      aria-invalid={error ? true : invalid}
      aria-describedby={fieldDescription(id, describedBy, hint, error)}
      {...props}
    />
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
