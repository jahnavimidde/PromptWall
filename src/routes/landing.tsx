/**
 * Landing page route
 *
 * Serves the interactive PromptWall demo at GET /.
 * This is a thin router that delegates to the TSX view.
 */

import { Hono } from "hono";
import LandingPage from "../views/landing/page";

export const landingRoutes = new Hono();

/**
 * GET / – Interactive PromptWall demo landing page
 */
landingRoutes.get("/", (c) => {
	return c.html(<LandingPage />);
});
