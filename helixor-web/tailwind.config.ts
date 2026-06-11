import type { Config } from "tailwindcss";

/**
 * Helixor design tokens — v3 "vermilion" system.
 *
 * AESTHETIC COMMITMENT
 * --------------------
 * Brutalist terminal-manifesto. Warm charcoal canvas (browned blacks, not
 * neutral), cream text, one vermilion accent carrying all chrome emphasis
 * (pills, labels, CTAs, terminal output). Green appears ONLY as "the good
 * number" inside data cards — chart language, never chrome. Tier colors
 * keep alert semantics on the product pages.
 *
 * All values are our own; the genre is shared, the execution is original.
 */
const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // Warm charcoal scale. ink-0 = canvas, ink-12 = cream.
        ink: {
          0:  "#100d0c",
          1:  "#151110",
          2:  "#1a1615",
          3:  "#221d1b",
          4:  "#2c2624",
          5:  "#383130",
          6:  "#524a47",
          7:  "#6b625e",
          8:  "#857b76",
          9:  "#a59c96",
          10: "#cdc5be",
          11: "#e8e1d8",
          12: "#f4efe6",
        },
        accent: {
          DEFAULT: "#ff4f2e",
          bright:  "#ff7a5c",
          dim:     "#7a2a1a",
        },
        // "The good number" in data cards.
        data: {
          green: "#46d68c",
        },
        tier: {
          green:  "#34d399",
          yellow: "#fbbf24",
          red:    "#f87171",
        },
        chain: "#60a5fa",
        ok:    "#22c55e",
      },
      fontFamily: {
        sans: ["var(--font-sans)", "ui-sans-serif", "system-ui"],
        mono: ["var(--font-mono)", "ui-monospace", "monospace"],
      },
      fontSize: {
        "score": ["7rem", { lineHeight: "1", letterSpacing: "-0.04em", fontWeight: "500" }],
        "display-1": ["4.25rem", { lineHeight: "1.02", letterSpacing: "-0.03em", fontWeight: "500" }],
        "display-2": ["3rem", { lineHeight: "1.08", letterSpacing: "-0.02em", fontWeight: "500" }],
        "display-3": ["2rem", { lineHeight: "1.2", letterSpacing: "-0.015em", fontWeight: "500" }],
      },
      letterSpacing: { eyebrow: "0.14em" },
      animation: {
        "score-fill": "score-fill 0.9s cubic-bezier(0.16, 1, 0.3, 1) forwards",
        "heartbeat":  "heartbeat 2s ease-in-out infinite",
        "fade-in":    "fade-in 0.4s ease-out forwards",
        "blink":      "blink 1.1s step-end infinite",
        "rise":       "rise 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards",
      },
      keyframes: {
        "score-fill": {
          "0%":   { strokeDashoffset: "var(--circ)" },
          "100%": { strokeDashoffset: "var(--target)" },
        },
        "heartbeat": {
          "0%, 100%": { opacity: "1", transform: "scale(1)" },
          "50%":      { opacity: "0.6", transform: "scale(1.4)" },
        },
        "fade-in": { "0%": { opacity: "0" }, "100%": { opacity: "1" } },
        "blink":   { "0%, 100%": { opacity: "1" }, "50%": { opacity: "0" } },
        "rise": {
          "0%":   { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
      transitionTimingFunction: { "smooth-out": "cubic-bezier(0.16, 1, 0.3, 1)" },
    },
  },
  plugins: [],
};

export default config;
