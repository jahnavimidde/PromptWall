/**
 * @file DetectionRequest.ts
 * @module @promptwall/engine/detector
 *
 * Defines the input contract for all detectors.
 *
 * DetectionRequest is generic over its metadata type to allow callers to pass
 * strongly-typed, per-use-case context without resorting to `any`. All fields
 * are readonly; detectors must never mutate the request.
 */

/**
 * Immutable input passed to every {@link Detector.detect} call.
 *
 * @template TMeta - Shape of the caller-supplied metadata object.
 *   Defaults to `Record<string, unknown>` for untyped usage.
 *   Typed usage prevents accidental metadata contract drift between callers
 *   and detector implementations.
 *
 * @example Untyped usage
 * ```ts
 * const req: DetectionRequest = {
 *   content: "My name is Alice and my key is AKIAIOSFODNN7EXAMPLE",
 *   mimeType: "text/plain",
 * };
 * ```
 *
 * @example Typed metadata (future use)
 * ```ts
 * interface AuditMeta { requestId: string; userId: string }
 * const req: DetectionRequest<AuditMeta> = {
 *   content: "...",
 *   metadata: { requestId: "req-001", userId: "usr-42" },
 * };
 * ```
 */
export interface DetectionRequest<
  TMeta extends Record<string, unknown> = Record<string, unknown>,
> {
  /**
   * The source text or content to be analysed.
   * For binary content, callers should base64-encode and set `mimeType` accordingly.
   */
  readonly content: string;

  /**
   * Programming or natural language of the content.
   * Detectors MAY inspect this to skip incompatible requests (via `supports()`).
   *
   * Use BCP-47 tags for natural language (`"en"`, `"fr-CA"`) and
   * IANA-style names for programming languages (`"typescript"`, `"python"`).
   */
  readonly language?: string;

  /**
   * IANA MIME type describing the content format.
   * Detectors MAY inspect this to skip incompatible requests (via `supports()`).
   *
   * @example "text/plain"
   * @example "application/json"
   * @example "image/png"
   */
  readonly mimeType?: string;

  /**
   * Caller-supplied metadata, strongly typed via `TMeta`.
   * Detectors must treat this as read-only; do not write or delete fields.
   */
  readonly metadata?: Readonly<TMeta>;
}
