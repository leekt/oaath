/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import React from "react";
import { Wordmark } from "../brand/Wordmark.jsx";
export function SiteHeader({
  name,
  sub,
  home = "/",
  links = [],
  right,
  onNavigate,
  className = "",
  ...props
}) {
  return (
    <header className={`ds-header ${className}`} {...props}>
      <Wordmark name={name} sub={sub} as="a" href={home} />
      <nav aria-label="Main navigation">
        {links.map((link) => (
          <a
            key={link.label}
            href={link.href}
            aria-current={link.active ? "page" : undefined}
            onClick={
              onNavigate ? (event) => onNavigate(link, event) : undefined
            }
          >
            {link.label}
          </a>
        ))}
        {right}
      </nav>
    </header>
  );
}
