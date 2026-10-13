/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import React from "react";
import { Button } from "./Button.jsx";
export const IconButton = React.forwardRef(function IconButton(
  { label, active, className = "", ...props },
  ref,
) {
  return (
    <Button
      ref={ref}
      aria-label={label}
      title={label}
      aria-pressed={active}
      className={`ds-icon-button ${className}`}
      {...props}
    />
  );
});
