import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// WCAG 2.x contrast computed from the real :root tokens in globals.css, for each
// foreground/background pair the stylesheets actually use for text.
const css = readFileSync(join(__dirname, "globals.css"), "utf8");
const root = css.slice(css.indexOf(":root {"), css.indexOf("}", css.indexOf(":root {")));
const TOKENS = Object.fromEntries(
  [...root.matchAll(/--([a-z-]+):\s*(#[0-9a-fA-F]{6})\s*;/g)].map((m) => [m[1], m[2]]),
);

function color(v: string): string {
  if (v.startsWith("#")) return v;
  const hex = TOKENS[v];
  if (!hex) throw new Error(`unknown token --${v}`);
  return hex;
}

function luminance(hex: string): number {
  const [r, g, b] = [1, 3, 5].map((i) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

export function contrast(fg: string, bg: string): number {
  const [a, b] = [luminance(color(fg)), luminance(color(bg))].sort((x, y) => y - x);
  return (a + 0.05) / (b + 0.05);
}

// [what, foreground, background, minimum]
const TEXT: Array<[string, string, string, number]> = [
  ["body text on canvas", "text", "canvas", 4.5],
  ["secondary text on canvas", "muted", "canvas", 4.5],
  ["secondary text on white", "muted", "surface", 4.5],
  ["secondary text on sunken surface", "muted", "surface-sunken", 4.5],
  ["secondary text in error panel", "muted", "danger-soft", 4.5],
  ["secondary text in warning panel", "muted", "warning-soft", 4.5],
  ["secondary text in info panel", "muted", "primary-soft", 4.5],
  ["input placeholder on white", "placeholder", "surface", 4.5],
  ["coral eyebrow on canvas", "coral-ink", "canvas", 4.5],
  ["coral eyebrow on white", "coral-ink", "surface", 4.5],
  ["PILOT tag on coral tint", "coral-ink", "coral-soft", 4.5],
  ["links on white", "primary", "surface", 4.5],
  ["links on canvas", "primary", "canvas", 4.5],
  ["indigo text on indigo tint", "primary-ink", "primary-soft", 4.5],
  ["cyan evidence on white", "cyan-ink", "surface", 4.5],
  ["cyan tag on cyan tint", "cyan-ink", "cyan-soft", 4.5],
  ["green badge on green tint", "success-ink", "success-soft", 4.5],
  ["amber text on amber tint", "warning-ink", "warning-soft", 4.5],
  ["red text on red tint", "danger-ink", "danger-soft", 4.5],
  ["violet AI tag on violet tint", "violet-ink", "violet-soft", 4.5],
  ["button text on primary", "#ffffff", "primary", 4.5],
  ["button text on primary hover", "#ffffff", "primary-hover", 4.5],
  ["Approve text", "#ffffff", "success-ink", 4.5],
  ["sidebar text on navy", "sidebar-text", "sidebar", 4.5],
  ["sidebar captions on navy", "sidebar-muted", "sidebar", 4.5],
];

// Non-text UI (focus indicators): WCAG 1.4.11 needs >= 3:1.
const UI: Array<[string, string, string, number]> = [
  ["focus outline on white", "primary", "surface", 3],
  ["focus outline on canvas", "primary", "canvas", 3],
];

describe("design-token contrast", () => {
  it.each([...TEXT, ...UI])("%s", (_what, fg, bg, min) => {
    expect(contrast(fg, bg)).toBeGreaterThanOrEqual(min);
  });
});
