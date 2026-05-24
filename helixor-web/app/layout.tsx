import "./globals.css";

import type { Metadata } from "next";
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";
import { Header } from "@/components/layout/Header";
import { Footer } from "@/components/layout/Footer";
import { DemoBanner } from "@/components/layout/DemoBanner";
import { isMock } from "@/lib/api";

export const metadata: Metadata = {
  metadataBase: new URL("https://helixor.xyz"),
  title: {
    default: "Helixor — On-chain trust scoring for AI agents on Solana",
    template: "%s · Helixor",
  },
  description:
    "Helixor is a permissionless, BFT-consensus trust scoring layer for autonomous agents on Solana. Every score is signed by 3 of 5 independent oracle nodes and anchored on-chain.",
  openGraph: {
    title: "Helixor — On-chain trust scoring for AI agents on Solana",
    description:
      "Paste any Solana agent wallet to see its trust score. BFT-signed, on-chain, permissionless.",
    type: "website",
    url: "https://helixor.xyz",
    siteName: "Helixor",
  },
  twitter: {
    card: "summary_large_image",
    title: "Helixor",
    description: "On-chain trust scoring for AI agents on Solana.",
  },
  robots: { index: true, follow: true },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`${GeistSans.variable} ${GeistMono.variable}`}
    >
      <body className="grain min-h-screen bg-ink-0 text-ink-12 antialiased">
        <div className="fixed top-0 left-0 right-0 z-50">
          <DemoBanner />
          <Header />
        </div>
        {/* Spacer matches actual chrome height: 64px header + 36px banner when in mock mode. */}
        <div className={isMock() ? "h-[100px]" : "h-16"} aria-hidden />
        <main>{children}</main>
        <Footer />
      </body>
    </html>
  );
}
