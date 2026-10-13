/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import * as React from "react";
export interface NativeSelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  label?: React.ReactNode;
  hint?: React.ReactNode;
  error?: React.ReactNode;
  dense?: boolean;
  options?: (string | { value: string; label: string; disabled?: boolean })[];
}
export interface SelectProps extends Omit<NativeSelectProps, "onChange"> {
  onChange?: (value: string) => void;
  onValueChange?: (value: string) => void;
}
export declare const NativeSelect: React.ForwardRefExoticComponent<
  NativeSelectProps & React.RefAttributes<HTMLSelectElement>
>;
export declare const Select: React.ForwardRefExoticComponent<
  SelectProps & React.RefAttributes<HTMLSelectElement>
>;
