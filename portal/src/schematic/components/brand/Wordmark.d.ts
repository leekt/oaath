/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import * as React from "react";
export interface WordmarkProps extends React.HTMLAttributes<HTMLElement> {
  name?: string;
  sub?: string;
  size?: number;
  as?: "span" | "a";
  href?: string | undefined;
  target?: string;
  rel?: string;
}
export declare const Wordmark: React.ForwardRefExoticComponent<
  WordmarkProps & React.RefAttributes<HTMLElement>
>;
