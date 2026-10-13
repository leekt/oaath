/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import * as React from "react";
export interface ButtonStyleProps {
  variant?:
    "primary" | "dark" | "secondary" | "ghost" | "destructive" | "choice";
  size?: "sm" | "md" | "lg";
  block?: boolean;
  className?: string;
}
export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>, ButtonStyleProps {
  icon?: React.ReactNode;
  iconRight?: React.ReactNode;
  loading?: boolean;
}
export declare function buttonClass(props?: ButtonStyleProps): string;
export declare const Button: React.ForwardRefExoticComponent<
  ButtonProps & React.RefAttributes<HTMLButtonElement>
>;
export declare const LinkButton: React.ForwardRefExoticComponent<
  React.AnchorHTMLAttributes<HTMLAnchorElement> &
    ButtonStyleProps &
    React.RefAttributes<HTMLAnchorElement>
>;
