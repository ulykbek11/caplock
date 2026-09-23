import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import YAML from "yaml";
import { z } from "zod";
import { CONFIG_NAME, STATE_DIR_NAME } from "./constants.js";

const schema = z.object({ schemaVersion: z.literal(1), defaults: z.object({ network: z.enum(["none", "host"]).default("none") }).default({ network: "none" }), execution: z.object({ timeoutSeconds: z.number().int().min(1).max(3600).default(300) }).default({ timeoutSeconds: 300 }), ui: z.object({ color: z.enum(["auto", "always", "never"]).default("auto") }).default({ color: "auto" }) }).strict();
export type CaplockConfig = z.infer<typeof schema>;
export const configPath = (root: string): string => path.join(root, STATE_DIR_NAME, CONFIG_NAME);
export const defaultConfig = (): CaplockConfig => ({ schemaVersion: 1, defaults: { network: "none" }, execution: { timeoutSeconds: 300 }, ui: { color: "auto" } });
export function readConfig(root: string): CaplockConfig { const file = configPath(root); return existsSync(file) ? schema.parse(YAML.parse(readFileSync(file, "utf8"))) : defaultConfig(); }
export function writeConfig(root: string, config: CaplockConfig = defaultConfig()): void { mkdirSync(path.dirname(configPath(root)), { recursive: true, mode: 0o700 }); writeFileSync(configPath(root), YAML.stringify(config), { encoding: "utf8", mode: 0o600 }); }
