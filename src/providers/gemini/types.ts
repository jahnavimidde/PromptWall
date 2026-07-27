import { z } from "zod";

/**
 * Gemini API types & schemas
 * Reference: https://ai.google.dev/api/rest/v1beta/models/generateContent
 */

export interface GeminiInlineData {
  mimeType: string;
  data: string;
}

export interface GeminiPart {
  text?: string;
  inlineData?: GeminiInlineData;
  functionCall?: Record<string, unknown>;
  functionResponse?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface GeminiContent {
  role?: "user" | "model" | string;
  parts: GeminiPart[];
}

export interface GeminiSystemInstruction {
  parts: GeminiPart[];
}

export interface GeminiGenerationConfig {
  temperature?: number;
  topP?: number;
  topK?: number;
  candidateCount?: number;
  maxOutputTokens?: number;
  stopSequences?: string[];
  responseMimeType?: string;
  [key: string]: unknown;
}

export interface GeminiSafetySetting {
  category: string;
  threshold: string;
}

export interface GeminiGenerateContentRequest {
  contents: GeminiContent[];
  systemInstruction?: GeminiSystemInstruction;
  generationConfig?: GeminiGenerationConfig;
  safetySettings?: GeminiSafetySetting[];
  tools?: unknown[];
  model?: string;
  stream?: boolean;
  [key: string]: unknown;
}

export interface GeminiCandidate {
  content?: GeminiContent;
  finishReason?: string;
  index?: number;
  safetyRatings?: unknown[];
}

export interface GeminiUsageMetadata {
  promptTokenCount?: number;
  candidatesTokenCount?: number;
  totalTokenCount?: number;
}

export interface GeminiGenerateContentResponse {
  candidates?: GeminiCandidate[];
  usageMetadata?: GeminiUsageMetadata;
  modelVersion?: string;
  error?: {
    code: number;
    message: string;
    status?: string;
    details?: unknown[];
  };
  [key: string]: unknown;
}

// Zod schemas for validation & safety
export const GeminiPartSchema = z
  .object({
    text: z.string().optional(),
    inlineData: z
      .object({
        mimeType: z.string(),
        data: z.string(),
      })
      .optional(),
  })
  .passthrough();

export const GeminiContentSchema = z
  .object({
    role: z.string().optional(),
    parts: z.array(GeminiPartSchema),
  })
  .passthrough();

export const GeminiCandidateSchema = z
  .object({
    content: GeminiContentSchema.optional(),
    finishReason: z.string().optional(),
    index: z.number().optional(),
  })
  .passthrough();

export const GeminiUsageMetadataSchema = z
  .object({
    promptTokenCount: z.number().optional(),
    candidatesTokenCount: z.number().optional(),
    totalTokenCount: z.number().optional(),
  })
  .passthrough();

export const GeminiGenerateContentResponseSchema = z
  .object({
    candidates: z.array(GeminiCandidateSchema).optional(),
    usageMetadata: GeminiUsageMetadataSchema.optional(),
    modelVersion: z.string().optional(),
  })
  .passthrough();
