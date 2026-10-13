/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import React from "react";
import { Button } from "./Button.jsx";

/** A choice with supporting text; shared defaults own its layout and states. */
export const ChoiceButton = React.forwardRef(function ChoiceButton(
  { label, description, icon, ...props },
  ref,
) {
  return (
    <Button ref={ref} variant="choice" icon={icon} {...props}>
      <span className="ds-choice-copy">
        <span className="ds-choice-title">{label}</span>
        {description && (
          <span className="ds-choice-description">{description}</span>
        )}
      </span>
    </Button>
  );
});
