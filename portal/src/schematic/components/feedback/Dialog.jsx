/* Generated from taek-design-system. Run scripts/sync.mjs in that repository. */
import React from "react";
import { createPortal } from "react-dom";
/** The native modal owns focus containment, inert surroundings and Escape semantics. */
export function Dialog({
  open,
  onClose,
  title,
  description,
  kicker,
  children,
  footer,
  width = 560,
  dismissible = true,
  className = "",
  onKeyDown,
  ...props
}) {
  const ref = React.useRef(null);
  const titleId = React.useId();
  const descriptionId = React.useId();
  React.useEffect(() => {
    if (!open || !ref.current) return;
    const dialog = ref.current;
    const opener = document.activeElement;
    const oldOverflow = document.body.style.overflow;
    dialog.showModal();
    const autofocus = dialog.querySelector(
      '[autofocus], [data-ds-autofocus="true"]',
    );
    if (autofocus instanceof HTMLElement && !autofocus.matches(":disabled"))
      autofocus.focus();
    document.body.style.overflow = "hidden";
    return () => {
      dialog.close();
      document.body.style.overflow = oldOverflow;
      if (opener instanceof HTMLElement && opener.isConnected) opener.focus();
    };
  }, [open]);
  if (!open || typeof document === "undefined") return null;
  return createPortal(
    <dialog
      ref={ref}
      className={`ds-dialog ${className}`}
      style={{ "--dialog-width": `${width}px` }}
      aria-labelledby={title ? titleId : undefined}
      aria-describedby={description ? descriptionId : undefined}
      onKeyDown={(event) => {
        onKeyDown?.(event);
        if (event.defaultPrevented || event.key !== "Tab") return;
        const controls = [
          ...event.currentTarget.querySelectorAll(
            'button, [href], input, select, textarea, summary, [tabindex], [contenteditable="true"]',
          ),
        ].filter(
          (control) =>
            !control.disabled &&
            control.tabIndex >= 0 &&
            control.getClientRects().length,
        );
        const first = controls[0],
          last = controls[controls.length - 1];
        if (!first) {
          event.preventDefault();
          event.currentTarget.focus();
        } else if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }}
      onCancel={(event) => {
        event.preventDefault();
        if (dismissible) onClose?.();
      }}
      onClick={(event) => {
        if (dismissible && event.target === event.currentTarget) {
          const bounds = event.currentTarget.getBoundingClientRect();
          if (
            event.clientX < bounds.left ||
            event.clientX > bounds.right ||
            event.clientY < bounds.top ||
            event.clientY > bounds.bottom
          )
            onClose?.();
        }
      }}
      {...props}
    >
      <div className="ds-dialog-head">
        {kicker && <p className="ds-eyebrow">{kicker}</p>}
        {title && <h2 id={titleId}>{title}</h2>}
        {description && (
          <p id={descriptionId} className="ds-page-description">
            {description}
          </p>
        )}
        {dismissible && (
          <button
            type="button"
            className="ds-dialog-close ds-button ds-button--ghost"
            aria-label="Close dialog"
            onClick={onClose}
          >
            ×
          </button>
        )}
      </div>
      <div className="ds-dialog-body">{children}</div>
      {footer && <div className="ds-dialog-foot">{footer}</div>}
    </dialog>,
    document.body,
  );
}
