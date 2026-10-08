/**
 * Every failure carries a structured `code`; callers branch on it, never on
 * the message. `status` is the HTTP status for service answers, 0 otherwise.
 *
 * @author taek <leekt216@gmail.com>
 */
export class AutomationError extends Error {
  readonly code: string;
  readonly status: number;
  constructor(code: string, status: number, message: string = code) {
    super(message);
    this.name = "AutomationError";
    this.code = code;
    this.status = status;
  }
}
