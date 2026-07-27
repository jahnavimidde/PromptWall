import { z } from "zod";

export const CodexRequestSchema = z
  .object({
    model: z.string().optional(),
    instructions: z.unknown().optional(),
    input: z.unknown().optional(),
    stream: z.boolean().optional(),
  })
  .passthrough();

export type CodexRequest = z.infer<typeof CodexRequestSchema>;
export type CodexResponse = Record<string, unknown>;
