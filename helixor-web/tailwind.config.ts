import type { Config } from "tailwindcss";

/**
 * Helixor design tokens.
 *
 * AESTHETIC COMMITMENT
 * --------------------
 * Monochrome. The site has NO accent color. The only chromatic moments are
 * the three alert tiers (GREEN/YELLOW/RED), the explorer-link blue, and a
 * single status-OK green used for cluster heartbeat dots. Everything else
 * is a step on a 12-stop grayscale.
 *
 * The grayscale is custom — not Tailwind defaults, not "neutral", not
 * "zinc". The stops are tuned for OLED-black backgrounds with white text,
 * where the Tailwind default neutral palette looks dead-flat. These stops
 * give a perceptual gradient.
 */
const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // The grayscale. ink-0 is the page background; ink-12 is pure white.
        // Numbered (not named) so semantic use is explicit at the call site.
        ink: {
          0:  "#000000",
          1:  "#0a0a0a",
          2:  "#111111",
          3:  "#1a1a1a",
          4:  "#262626",
          5:  "#333333",
          6:  "#4d4d4d",
          7:  "#666666",
          8:  "#808080",
          9:  "#a3a3a3",
          10: "#cccccc",
          11: "#e6e6e6",
          12: "#ffffff",
        },
        // The ONLY chromatic palette. Used for alert tier badges and the
        // matching score gauge. Never used for chrome, buttons, or links.
        tier: {
          green:  "#34d399",
          yellow: "#fbbf24",
          red:    "#f87171",
        },
        // Explorer-link blue. Distinct from chrome so users learn "blue =
        // off-site, on-chain proof."
        chain: "#60a5fa",
        // Heartbeat OK dot. Quieter than tier.green so it doesn't compete.
        ok:    "#22c55e",
      },
      fontFamily: {
        // Geist (Vercel-built) — sharper than Inter, designed for technical
        // products, not a default in any framework.
        sans: ["var(--font-geist-sans)", "ui-sans-serif", "system-ui"],
        mono: ["var(--font-geist-mono)", "ui-monospace", "monospace"],
      },
      fontSize: {
        // Custom display sizes tuned for the score widget + hero numerals.
        // The score is the loudest number on the page; it gets its own size.
        "score": ["7rem", { lineHeight: "1", letterSpacing: "-0.04em", fontWeight: "500" }],
        "display-1": ["4.5rem", { lineHeight: "1.05", letterSpacing: "-0.035em", fontWeight: "500" }],
        "display-2": ["3rem", { lineHeight: "1.1", letterSpacing: "-0.025em", fontWeight: "500" }],
        "display-3": ["2rem", { lineHeight: "1.2", letterSpacing: "-0.02em", fontWeight: "500" }],
      },
      letterSpacing: {
        // Used for ALL-CAPS labels (section headings, table headers).
        eyebrow: "0.14em",
      },
      animation: {
        // The score gauge fills in on first paint; the hero number ticks up.
        // No other animation in the site except the heartbeat pulse on /network.
        "score-fill": "score-fill 0.9s cubic-bezier(0.16, 1, 0.3, 1) forwards",
        "heartbeat":  "heartbeat 2s ease-in-out infinite",
        "fade-in":    "fade-in 0.4s ease-out forwards",
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
        "fade-in": {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        "rise": {
          "0%":   { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
      transitionTimingFunction: {
        "smooth-out": "cubic-bezier(0.16, 1, 0.3, 1)",
      },
    },
  },
  plugins: [],
};

export default config;
