import type { MetadataRoute } from "next";

/**
 * Web app manifest — installable PWA metadata + brand chrome colors.
 * theme/background use the warm-ink canvas so the install/splash matches
 * the site exactly.
 */
export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "Phylanx — Trust scores no one can fake",
    short_name: "Phylanx",
    description:
      "On-chain trust scoring for autonomous agents on Solana. Every score is computed by independent oracle nodes and threshold-signed on-chain.",
    start_url: "/",
    display: "standalone",
    background_color: "#100d0c",
    theme_color: "#100d0c",
    icons: [
      { src: "/icon.svg", sizes: "any", type: "image/svg+xml", purpose: "any" },
    ],
  };
}
