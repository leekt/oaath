/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import React from "react";
/** The brand is typography, including when used as a home link. */
export const Wordmark = React.forwardRef(function Wordmark(
  {
    name = "taek.tech",
    sub,
    size,
    as: Tag = "span",
    className = "",
    style,
    ...props
  },
  ref,
) {
  return (
    <Tag
      ref={ref}
      className={`ds-wordmark ${className}`}
      style={{ ...(size ? { fontSize: size } : {}), ...style }}
      {...props}
    >
      {name}
      {sub && <span className="ds-wordmark-sub">/ {sub}</span>}
    </Tag>
  );
});
