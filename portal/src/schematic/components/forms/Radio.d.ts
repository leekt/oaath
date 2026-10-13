/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import * as React from "react";
export interface RadioProps extends Omit<
  React.InputHTMLAttributes<HTMLInputElement>,
  "onChange"
> {
  label: React.ReactNode;
  hint?: React.ReactNode;
  onChange?: (value: string) => void;
}
export declare const Radio: React.ForwardRefExoticComponent<
  RadioProps & React.RefAttributes<HTMLInputElement>
>;
