import "@fontsource-variable/space-grotesk";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/500.css";
import "@fontsource/ibm-plex-mono/600.css";
import "./globals.css";

import type { Metadata } from "next";
import { Header } from "@/components/layout/Header";
import { Footer } from "@/components/layout/Footer";
import { DemoBanner } from "@/components/layout/DemoBanner";
import { isMock } from "@/lib/api";

export const metadata: Metadata = {
  metadataBase: new URL("https://helixor.xyz"),
  title: {
    default: "Helixor — Trust scores no one can fake",
    template: "%s · Helixor",
  },
  description:
    "Helixor is a permissionless trust layer for autonomous agents on Solana. Every score is computed by 5 independent oracle nodes, signed by at least 3 of 5 cluster keys, and anchored on-chain.",
  openGraph: {
    title: "Helixor — Trust scores no one can fake",
    description:
      "Paste any Solana agent wallet to see its trust score. Threshold-signed, on-chain, permissionless.",
    type: "website",
    url: "https://helixor.xyz",
    siteName: "Helixor",
  },
  twitter: {
    card: "summary_large_image",
    title: "Helixor",
    description: "Trust scores no one can fake.",
  },
  robots: { index: true, follow: true },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="grain min-h-screen bg-ink-0 text-ink-12 antialiased">
        <div className="fixed top-0 left-0 right-0 z-50">
          <DemoBanner />
          <Header />
        </div>
        {/* Spacer matches chrome height: 64px header + 36px banner in mock mode. */}
        <div className={isMock() ? "h-[100px]" : "h-16"} aria-hidden />
        <main>{children}</main>
        <Footer />
      </body>
    </html>
  );
}
