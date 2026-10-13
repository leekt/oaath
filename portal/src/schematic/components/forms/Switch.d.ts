/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import * as React from "react";
export interface SwitchProps extends Omit<
  React.ButtonHTMLAttributes<HTMLButtonElement>,
  "onChange"
> {
  label?: React.ReactNode;
  hint?: React.ReactNode;
  checked?: boolean;
  onChange?: (checked: boolean) => void;
  onCheckedChange?: (checked: boolean) => void;
}
export declare const Switch: React.ForwardRefExoticComponent<
  SwitchProps & React.RefAttributes<HTMLButtonElement>
>;
