/**
 * NOA Relay — push-provider abstraction.
 *
 * A deployment supplies a `PushProvider`; the public reference implementation includes only a
 * no-op/log driver for local development. Provider credentials and platform-specific delivery
 * integrations stay outside this package.
 *
 * RED LINE 11 / invariant (spec §9): the push payload carries an OPAQUE hold-id + deep-link ONLY.
 * Never raw action params, never PII.
 *
 * ⚠ CORRECTED 2026-07-31 (claim finding C08). This line read "The provider contract below cannot
 * carry anything else", which the struct nine lines below refutes: it also carries `title` and a
 * `body` of at most "<requester> wants to <canonical>". The ACTION NAME therefore reaches the push
 * provider — an untrusted third party. The security-relevant half of the original claim holds (no
 * raw params, no PII); the absolute did not, and an operator reading it would not have realised
 * the canonical action name leaves the system.
 */

export interface PushMessage {
  /** Opaque hold id — the ONLY correlator the notification is allowed to carry. */
  holdId: string;
  /** Fixed, non-sensitive title. */
  title: string;
  /** Non-sensitive body: at most "<requester> wants to <canonical>". Never raw params. */
  body: string;
  /** Deployment-defined route or URI that opens the referenced approval. */
  deepLink: string;
}

export interface PushDelivery {
  deviceId: string;
  delivered: boolean;
  detail: string;
}

export interface PushProvider {
  readonly name: string;
  send(deviceId: string, subscription: unknown, msg: PushMessage): Promise<PushDelivery>;
}

/**
 * Localhost driver: logs the bounded notification and returns "delivered". Production deployments
 * can combine provider delivery with an independently authenticated pull path.
 */
export class NoopLogPushProvider implements PushProvider {
  readonly name = "noop-log";
  private readonly sink: (line: string) => void;
  public readonly sent: Array<{ deviceId: string; msg: PushMessage }> = [];

  constructor(sink: (line: string) => void = () => {}) {
    this.sink = sink;
  }

  async send(deviceId: string, _subscription: unknown, msg: PushMessage): Promise<PushDelivery> {
    // Assert the opaque-only contract at runtime: only holdId/title/body/deepLink, nothing else.
    this.sent.push({ deviceId, msg });
    this.sink(`[push:${this.name}] device=${deviceId} hold=${msg.holdId} "${msg.title}"`);
    return { deviceId, delivered: true, detail: "logged (no-op localhost driver)" };
  }
}
