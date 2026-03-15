import { defineConfig } from "tsup";

export default defineConfig({
	entry: ["src/register.ts"],
	format: ["esm"],
	outDir: "dist/bundle",
	splitting: false,
	// Bundle all dependencies into a single file for OpenClaw extension deployment
	noExternal: [/@sentinel\/types/, /zod/],
});
