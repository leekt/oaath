/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import React from "react";
export function AppShell({
  header,
  footer,
  children,
  className = "",
  density = "demo",
  ...props
}) {
  return (
    <div className={`ds-shell ${className}`} data-density={density} {...props}>
      {header}
      {children}
      {footer}
    </div>
  );
}
export function WorkspaceShell({
  sidebar,
  header,
  children,
  className = "",
  ...props
}) {
  return (
    <div className={`ds-workspace-shell ${className}`} {...props}>
      <aside className="ds-workspace-sidebar">{sidebar}</aside>
      <div className="ds-workspace-body">
        {header}
        <main className="ds-workspace-main">{children}</main>
      </div>
    </div>
  );
}
export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
  className = "",
  children,
  ...props
}) {
  return (
    <div className={`ds-page-header ${className}`} {...props}>
      <div>
        {eyebrow && <p className="ds-eyebrow">{eyebrow}</p>}
        <h1>{title}</h1>
        {description && <p className="ds-page-description">{description}</p>}
        {children}
      </div>
      {actions && <div className="ds-actions">{actions}</div>}
    </div>
  );
}
export function Stack({ children, className = "", ...props }) {
  return (
    <div className={`ds-stack ${className}`} {...props}>
      {children}
    </div>
  );
}

export function SplitLayout({ children, className = "", ...props }) {
  return (
    <div className={`ds-split ${className}`} {...props}>
      {children}
    </div>
  );
}

export function CanvasWorkspace({
  library,
  inspector,
  children,
  className = "",
  ...props
}) {
  return (
    <div
      className={`ds-canvas-workspace${inspector ? " has-inspector" : ""} ${className}`}
      {...props}
    >
      <aside className="ds-canvas-library">{library}</aside>
      <div className="ds-canvas-column">{children}</div>
      {inspector && <aside className="ds-canvas-inspector">{inspector}</aside>}
    </div>
  );
}
