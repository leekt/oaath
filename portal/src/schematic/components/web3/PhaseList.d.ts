/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import * as React from "react";
export interface Phase {
  id?: string;
  label?: string;
  title?: string;
  detail?: string;
  description?: string;
  status: "complete" | "current" | "running" | "waiting" | "failed";
  statusText?: string;
}
export interface PhaseListProps extends React.OlHTMLAttributes<HTMLOListElement> {
  phases: Phase[];
}
export declare function PhaseList(props: PhaseListProps): React.ReactElement;
