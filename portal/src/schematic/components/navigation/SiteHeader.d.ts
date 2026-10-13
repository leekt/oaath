/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import * as React from "react";
export interface SiteHeaderProps extends React.HTMLAttributes<HTMLElement> {
  name?: string;
  sub?: string;
  home?: string;
  links?: { label: string; href: string; active?: boolean }[];
  right?: React.ReactNode;
  onNavigate?: (
    link: { label: string; href: string; active?: boolean },
    event: React.MouseEvent<HTMLAnchorElement>,
  ) => void;
}
export declare function SiteHeader(props: SiteHeaderProps): React.ReactElement;
