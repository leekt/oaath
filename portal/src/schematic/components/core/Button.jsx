/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import React from "react";
export function buttonClass({
  variant = "secondary",
  size = "md",
  className = "",
  block = false,
} = {}) {
  return `ds-button ds-button--${variant} ds-button--${size}${block ? " ds-button--block" : ""} ${className}`;
}
export const Button = React.forwardRef(function Button(
  {
    variant,
    size,
    icon,
    iconRight,
    children,
    block,
    loading = false,
    disabled,
    className,
    type = "button",
    ...props
  },
  ref,
) {
  return (
    <button
      data-slot="button"
      ref={ref}
      type={type}
      className={buttonClass({ variant, size, block, className })}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      {...props}
    >
      {loading ? <span className="ds-spinner" aria-hidden="true" /> : icon}
      {children}
      {iconRight}
    </button>
  );
});
export const LinkButton = React.forwardRef(function LinkButton(
  { variant, size, block, className, children, ...props },
  ref,
) {
  return (
    <a
      ref={ref}
      className={buttonClass({ variant, size, block, className })}
      {...props}
    >
      {children}
    </a>
  );
});
