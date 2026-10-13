/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import * as React from "react";
export interface PanelProps extends Omit<
  React.HTMLAttributes<HTMLElement>,
  "title"
> {
  title?: React.ReactNode;
  meta?: string;
  actions?: React.ReactNode;
  fig?: React.ReactNode;
  frame?: "ink" | "hair";
  padding?: number | string;
  as?: "section" | "div" | "article";
}
export declare const Panel: React.ForwardRefExoticComponent<
  PanelProps & React.RefAttributes<HTMLElement>
>;
export declare const Surface: React.ForwardRefExoticComponent<
  React.HTMLAttributes<HTMLElement> & {
    as?: "section" | "main" | "div" | "article";
  } & React.RefAttributes<HTMLElement>
>;
