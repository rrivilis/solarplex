import type { Config } from "tailwindcss";
import typography from "@tailwindcss/typography";

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        // Indigo-moonlight dark palette — hsl(225°) base, desaturated progressively
        surface: {
          0: "#111318",   // hsl(225,18%, 8%) — page background
          1: "#181a21",   // hsl(225,16%,11%) — sidebar, primary panels
          2: "#1f2129",   // hsl(225,14%,14%) — card backgrounds, inputs
          3: "#262932",   // hsl(225,12%,18%) — elevated surfaces, hover targets
          4: "#2d3040",   // hsl(225,10%,22%) — active separators, thumb
        },
        border: "#252833",   // hsl(225,13%,17%) — subtle panel borders
        // hsl(225, 8%,56%) — placeholder, secondary text. Was 40% lightness
        // (#5e626e): failed WCAG AA normal-text contrast (4.5:1) against
        // every surface in this palette, including the ones it's used on
        // most (surface-0/1/2 — 3.05/2.85/2.64:1). Bumped to clear AA
        // against surface-0/1/2; surface-3/4 ("elevated surfaces, hover
        // targets") still fall short (4.22/3.79:1) — avoid text-muted for
        // body copy on those two specifically, or size it ≥18.66px/14pt
        // bold there (WCAG's large-text threshold drops to 3:1). This is
        // now close to `subtle` in value — that's the actual cost of the
        // fix, not an oversight: the two tokens can't both stay AA-compliant
        // at small sizes on this narrow an 8–22%-lightness surface band
        // without converging. See tests/a11y and the accessibility audit
        // report for the full contrast sweep this was derived from.
        muted:  "#868a98",
        subtle: "#8c909b",   // hsl(225, 7%,58%) — tertiary text
        primary: "#dedfe3",  // hsl(220, 8%,88%) — primary text (warm-neutral)
        accent: {
          blue:   "#4f8ef7",
          green:  "#3ecf8e",
          amber:  "#f5a623",
          red:    "#f56565",
          purple: "#a78bfa",
        },
      },
      fontFamily: {
        sans:       ["Plus Jakarta Sans", "-apple-system", "BlinkMacSystemFont", "sans-serif"],
        mono:       ["JetBrains Mono", "Fira Code", "monospace"],
        // Wordmark typefaces — both OFL / FOSS
        grotesk:    ["Figtree", "Inter", "sans-serif"],      // Helvetica Neue replacement
        serif:      ["Merriweather", "Georgia", "serif"],    // warm organic counterpart
      },
      fontSize: {
        "2xs": "0.65rem",
      },
      boxShadow: {
        // Two-tier elevation scale, same spirit as the surface-0..4 color
        // scale — a shared vocabulary instead of each floating element
        // picking whichever bare Tailwind shadow-* keyword looked right at
        // the time (the app had shadow-lg, -xl, and -2xl all in use for
        // conceptually-identical dropdown/tooltip/modal tiers before this).
        // Two shadow layers each (a soft diffuse one + a tighter contact
        // one) rather than Tailwind's single-layer defaults — reads as more
        // "real" depth. Tuned darker/more opaque than Tailwind's black-10%
        // default: on this near-black palette (surface-0 #111318) a
        // light-theme-calibrated shadow all but disappears.
        "elevation-float": "0 4px 16px -2px rgba(0,0,0,0.45), 0 2px 6px -2px rgba(0,0,0,0.3)",
        "elevation-modal": "0 16px 40px -8px rgba(0,0,0,0.55), 0 4px 12px -4px rgba(0,0,0,0.35)",
      },
    },
  },
  plugins: [typography],
};

export default config;
