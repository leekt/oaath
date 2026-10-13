/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import React from "react";
export const Panel = React.forwardRef(function Panel(
  {
    title,
    meta,
    actions,
    fig,
    frame = "ink",
    padding,
    as: Tag = "section",
    className = "",
    style,
    children,
    ...props
  },
  ref,
) {
  return (
    <Tag
      ref={ref}
      className={`ds-panel ds-panel--${frame} ${className}`}
      style={{
        ...(padding != null
          ? {
              "--panel-gutter":
                typeof padding === "number" ? `${padding}px` : padding,
            }
          : {}),
        ...style,
      }}
      {...props}
    >
      {(title || meta || actions) && (
        <div className="ds-panel-head">
          <div>
            {title && <h2>{title}</h2>}
            {meta && <span className="ds-meta">{meta}</span>}
          </div>
          {actions}
        </div>
      )}
      <div className="ds-panel-body">{children}</div>
      {fig && <footer className="ds-panel-foot">{fig}</footer>}
    </Tag>
  );
});

export const Surface = React.forwardRef(function Surface(
  { as: Tag = "section", className = "", children, ...props },
  ref,
) {
  return (
    <Tag ref={ref} className={`ds-panel ds-surface ${className}`} {...props}>
      {children}
    </Tag>
  );
});
