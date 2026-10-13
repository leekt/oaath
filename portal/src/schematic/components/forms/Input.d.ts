/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import * as React from "react";
export interface InputProps extends Omit<
  React.InputHTMLAttributes<HTMLInputElement>,
  "prefix"
> {
  label?: React.ReactNode;
  hint?: React.ReactNode;
  error?: React.ReactNode;
  prefix?: React.ReactNode;
  suffix?: React.ReactNode;
  mono?: boolean;
  dense?: boolean;
}
export declare const Input: React.ForwardRefExoticComponent<
  InputProps & React.RefAttributes<HTMLInputElement>
>;
