/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import React from "react";
import { FormField, fieldDescription } from "./FormField.jsx";
export const NativeSelect = React.forwardRef(function NativeSelect(
  {
    label,
    hint,
    error,
    options,
    dense,
    className = "",
    id: suppliedId,
    "aria-describedby": describedBy,
    "aria-invalid": invalid,
    children,
    ...props
  },
  ref,
) {
  const generatedId = React.useId();
  const id = suppliedId || generatedId;
  const control = (
    <select
      data-ds-autofocus={props.autoFocus || undefined}
      ref={ref}
      id={id}
      className={`ds-input ds-select${dense ? " ds-input--dense" : ""} ${className}`}
      aria-invalid={error ? true : invalid}
      aria-describedby={fieldDescription(id, describedBy, hint, error)}
      {...props}
    >
      {options
        ? options.map((option) => {
            const item =
              typeof option === "string"
                ? { value: option, label: option }
                : option;
            return (
              <option
                key={item.value}
                value={item.value}
                disabled={item.disabled}
              >
                {item.label}
              </option>
            );
          })
        : children}
    </select>
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
/** Compatibility with the catalog's value callback; NativeSelect exposes native events. */
export const Select = React.forwardRef(function Select(
  { onChange, onValueChange, ...props },
  ref,
) {
  return (
    <NativeSelect
      ref={ref}
      onChange={(event) => {
        onChange?.(event.target.value);
        onValueChange?.(event.target.value);
      }}
      {...props}
    />
  );
});
