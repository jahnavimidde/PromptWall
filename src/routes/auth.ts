/**
 * @file auth.ts
 * @module src/routes
 *
 * REST API routes for authentication and user sessions (M7C).
 */

import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import { z } from "zod";
import { authMiddleware } from "../auth/middleware";
import { signUserToken, type JwtUserPayload } from "../auth/jwt";
import { UserStore } from "../auth/user-store";

export const authRoutes = new Hono();

const LoginSchema = z.object({
  email: z.string().trim().email("Valid email required"),
  password: z.string().trim().min(1, "Password is required"),
});

/**
 * POST /api/auth/login - Authenticate user and issue JWT token
 */
authRoutes.post("/login", zValidator("json", LoginSchema), async (c) => {
  const { email, password } = c.req.valid("json");
  const userStore = new UserStore();

  const user = await userStore.findUserByEmail(email);
  if (!user) {
    return c.json(
      {
        error: {
          message: "Invalid email or password",
          type: "invalid_credentials",
        },
      },
      401,
    );
  }

  const isValid = await userStore.verifyPassword(password, user.passwordHash);
  if (!isValid) {
    return c.json(
      {
        error: {
          message: "Invalid email or password",
          type: "invalid_credentials",
        },
      },
      401,
    );
  }

  const token = await signUserToken(user.id, user.email, user.role);

  return c.json({
    token,
    user: {
      id: user.id,
      email: user.email,
      role: user.role,
    },
  });
});

/**
 * GET /api/auth/me - Retrieve profile of authenticated user
 */
authRoutes.get("/me", authMiddleware, async (c) => {
  const user = c.get("user") as JwtUserPayload;

  return c.json({
    user: {
      id: user.sub,
      email: user.email,
      role: user.role,
    },
  });
});
