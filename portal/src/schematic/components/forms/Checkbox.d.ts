/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import * as React from "react";
export interface CheckboxProps extends Omit<
  React.InputHTMLAttributes<HTMLInputElement>,
  "onChange"
> {
  label: React.ReactNode;
  hint?: React.ReactNode;
  onChange?: (checked: boolean) => void;
  onCheckedChange?: (checked: boolean) => void;
}
export declare const Checkbox: React.ForwardRefExoticComponent<
  CheckboxProps & React.RefAttributes<HTMLInputElement>
>;
