/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import * as React from "react";
export interface DialogProps extends Omit<
  React.DialogHTMLAttributes<HTMLDialogElement>,
  "title" | "open" | "onClose"
> {
  open: boolean;
  onClose?: () => void;
  title?: React.ReactNode;
  description?: React.ReactNode;
  kicker?: React.ReactNode;
  footer?: React.ReactNode;
  width?: number;
  dismissible?: boolean;
}
export declare function Dialog(props: DialogProps): React.ReactElement | null;
