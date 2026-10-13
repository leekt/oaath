import { Button as Primitive } from "@base-ui/react/button";
import { buttonClass } from "../../schematic/components";
type Variant = "default" | "outline" | "ghost" | "choice";
export function Button({
  className = "",
  variant = "default",
  ...props
}: Primitive.Props & { variant?: Variant }) {
  const classes = (extra: string) =>
    buttonClass({
      variant:
        variant === "default"
          ? "dark"
          : variant === "choice"
            ? "choice"
            : variant === "ghost"
              ? "ghost"
              : "secondary",
      className: variant === "choice" ? `choice ${extra}` : extra,
    });
  return (
    <Primitive
      type="button"
      className={
        typeof className === "function"
          ? (state) => classes(className(state) || "")
          : classes(className)
      }
      {...props}
    />
  );
}
