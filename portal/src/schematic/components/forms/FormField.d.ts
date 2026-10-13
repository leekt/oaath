/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import * as React from "react";
export interface FormFieldProps extends React.HTMLAttributes<HTMLDivElement> {
  id?: string;
  label?: React.ReactNode;
  hint?: React.ReactNode;
  error?: React.ReactNode;
  required?: boolean;
}
export declare function FormField(props: FormFieldProps): React.ReactElement;
export declare function fieldDescription(
  id: string,
  describedBy?: string,
  hint?: React.ReactNode,
  error?: React.ReactNode,
): string | undefined;
