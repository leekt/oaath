/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import * as React from "react";
import type { ButtonProps } from "./Button";
export interface ChoiceButtonProps extends Omit<
  ButtonProps,
  "children" | "variant"
> {
  label: React.ReactNode;
  description?: React.ReactNode;
}
export declare const ChoiceButton: React.ForwardRefExoticComponent<
  ChoiceButtonProps & React.RefAttributes<HTMLButtonElement>
>;
