/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import * as React from "react";
export interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: React.ReactNode;
  hint?: React.ReactNode;
  error?: React.ReactNode;
  mono?: boolean;
}
export declare const Textarea: React.ForwardRefExoticComponent<
  TextareaProps & React.RefAttributes<HTMLTextAreaElement>
>;
