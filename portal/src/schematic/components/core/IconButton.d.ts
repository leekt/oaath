/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import * as React from "react";
import { ButtonProps } from "./Button";
export interface IconButtonProps extends ButtonProps {
  label: string;
  active?: boolean;
}
export declare const IconButton: React.ForwardRefExoticComponent<
  IconButtonProps & React.RefAttributes<HTMLButtonElement>
>;
