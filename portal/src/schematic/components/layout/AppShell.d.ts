/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import * as React from "react";
export interface AppShellProps extends React.HTMLAttributes<HTMLDivElement> {
  header?: React.ReactNode;
  footer?: React.ReactNode;
  density?: "demo" | "editorial" | "ops";
}
export declare function AppShell(props: AppShellProps): React.ReactElement;
export interface WorkspaceShellProps extends React.HTMLAttributes<HTMLDivElement> {
  sidebar: React.ReactNode;
  header?: React.ReactNode;
}
export declare function WorkspaceShell(
  props: WorkspaceShellProps,
): React.ReactElement;
export interface PageHeaderProps extends Omit<
  React.HTMLAttributes<HTMLDivElement>,
  "title"
> {
  eyebrow?: React.ReactNode;
  title: React.ReactNode;
  description?: React.ReactNode;
  actions?: React.ReactNode;
}
export declare function PageHeader(props: PageHeaderProps): React.ReactElement;
export declare function Stack(
  props: React.HTMLAttributes<HTMLDivElement>,
): React.ReactElement;
export declare function SplitLayout(
  props: React.HTMLAttributes<HTMLDivElement>,
): React.ReactElement;

export interface CanvasWorkspaceProps extends React.HTMLAttributes<HTMLDivElement> {
  library: React.ReactNode;
  inspector?: React.ReactNode;
}
export declare function CanvasWorkspace(
  props: CanvasWorkspaceProps,
): React.ReactElement;
