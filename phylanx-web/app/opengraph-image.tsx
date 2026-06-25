import { ImageResponse } from "next/og";

export const alt = "Phylanx — Trust scores no one can fake";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

/**
 * Dynamic OpenGraph / Twitter card. Rendered at build time (static route),
 * versioned in code, no external image asset to keep in sync. Brand palette:
 * warm-ink #100d0c canvas, cream #f4efe6 type, vermillion #ff4f2e accent.
 * Satori-safe: solid fills only, explicit display:flex on every container.
 */
export default function OpengraphImage() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          background: "#100d0c",
          padding: "72px 80px",
          fontFamily: "sans-serif",
        }}
      >
        {/* Lockup: Signal Shield mark (Satori-safe hexagons) + wordmark */}
        <div style={{ display: "flex", alignItems: "center", gap: 22 }}>
          <svg width="80" height="80" viewBox="0 0 100 100">
            <polygon points="50,6 88,28 88,72 50,94 12,72 12,28" fill="none" stroke="#f4efe6" strokeWidth="2" opacity="0.9" />
            <polygon points="50,20 76,35 76,65 50,80 24,65 24,35" fill="none" stroke="#f4efe6" strokeWidth="1.5" opacity="0.5" />
            <polygon points="50,33 64,41 64,59 50,67 36,59 36,41" fill="none" stroke="#ff6a45" strokeWidth="1.4" opacity="0.7" />
            <circle cx="50" cy="50" r="9" fill="#ff4f2e" />
            <circle cx="50" cy="50" r="3.4" fill="#fff3ee" />
          </svg>
          <div style={{ display: "flex", fontSize: 38, fontWeight: 700, color: "#f4efe6", letterSpacing: 9 }}>
            PHYLANX
          </div>
        </div>

        {/* Headline + sub */}
        <div style={{ display: "flex", flexDirection: "column" }}>
          <div style={{ display: "flex", fontSize: 78, fontWeight: 600, color: "#f4efe6", lineHeight: 1.04, letterSpacing: -2 }}>
            Trust scores no one can fake.
          </div>
          <div style={{ display: "flex", marginTop: 24, fontSize: 27, color: "#a59c96", lineHeight: 1.4, maxWidth: 880 }}>
            On-chain reputation for autonomous agents on Solana — computed by an independent oracle cluster, threshold-signed, anchored on-chain.
          </div>
        </div>

        {/* Footer */}
        <div style={{ display: "flex", alignItems: "center", gap: 16, fontSize: 23, color: "#857b76" }}>
          <div style={{ display: "flex", width: 13, height: 13, borderRadius: 99, background: "#ff4f2e" }} />
          <div style={{ display: "flex", color: "#cdc5be" }}>phylanx.com</div>
          <div style={{ display: "flex", color: "#524a47" }}>— threshold-signed · permissionless reads · Solana</div>
        </div>
      </div>
    ),
    { ...size },
  );
}
