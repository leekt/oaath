// shadcn/ui Base UI Button, themed with this portal's CSS instead of Tailwind.
// Source: https://ui.shadcn.com/r/styles/base-nova/button.json (MIT).
import { Button as ButtonPrimitive } from "@base-ui/react/button";
import { cva, type VariantProps } from "class-variance-authority";

const buttonVariants = cva("button", {
  variants: {
    variant: {
      default: "button-primary",
      outline: "button-outline",
      ghost: "button-ghost",
      choice: "choice",
    },
  },
  defaultVariants: { variant: "default" },
});

export function Button({
  className,
  variant,
  ...props
}: ButtonPrimitive.Props & VariantProps<typeof buttonVariants>) {
  return (
    <ButtonPrimitive
      type="button"
      data-slot="button"
      className={buttonVariants({ variant, className })}
      {...props}
    />
  );
}
