import "@fontsource-variable/space-grotesk";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/500.css";
import "@fontsource/ibm-plex-mono/600.css";
import "./globals.css";

import type { Metadata, Viewport } from "next";
import { Header } from "@/components/layout/Header";
import { Footer } from "@/components/layout/Footer";
import { DemoBanner } from "@/components/layout/DemoBanner";
import { isMock } from "@/lib/api";

export const metadata: Metadata = {
  metadataBase: new URL("https://phylanx.com"),
  applicationName: "Phylanx",
  title: {
    default: "Phylanx — Trust scores no one can fake",
    template: "%s · Phylanx",
  },
  description:
    "Phylanx is a permissionless trust layer for autonomous agents on Solana. Every score is computed by 5 independent oracle nodes, signed by at least 3 of 5 cluster keys, and anchored on-chain.",
  keywords: [
    "AI agent reputation",
    "on-chain trust score",
    "Solana agent identity",
    "autonomous agent security",
    "agent reputation oracle",
    "threshold-signed certificates",
    "DeFi agent credit",
    "permissionless trust layer",
  ],
  authors: [{ name: "Phylanx" }],
  creator: "Phylanx",
  publisher: "Phylanx",
  category: "technology",
  // Canonical for the homepage; per-route pages set their own.
  alternates: { canonical: "/" },
  openGraph: {
    title: "Phylanx — Trust scores no one can fake",
    description:
      "Paste any Solana agent wallet to see its trust score. Threshold-signed, on-chain, permissionless.",
    type: "website",
    url: "https://phylanx.com",
    siteName: "Phylanx",
    locale: "en_US",
  },
  twitter: {
    card: "summary_large_image",
    title: "Phylanx — Trust scores no one can fake",
    description: "On-chain trust scoring for autonomous agents on Solana.",
    creator: "@phylanxhq",
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      "max-image-preview": "large",
      "max-snippet": -1,
      "max-video-preview": -1,
    },
  },
};

export const viewport: Viewport = {
  themeColor: "#100d0c",
  colorScheme: "dark",
};

// Site-wide structured data (schema.org) for rich results. Organization +
// WebSite + SoftwareApplication, cross-linked by @id.
const jsonLd = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "Organization",
      "@id": "https://phylanx.com/#organization",
      name: "Phylanx",
      url: "https://phylanx.com",
      logo: "https://phylanx.com/icon.svg",
      description:
        "On-chain trust scoring for autonomous agents on Solana.",
      sameAs: ["https://github.com/phylanx"],
    },
    {
      "@type": "WebSite",
      "@id": "https://phylanx.com/#website",
      url: "https://phylanx.com",
      name: "Phylanx",
      description: "Trust scores no one can fake.",
      publisher: { "@id": "https://phylanx.com/#organization" },
      inLanguage: "en",
    },
    {
      "@type": "SoftwareApplication",
      name: "Phylanx",
      applicationCategory: "SecurityApplication",
      operatingSystem: "Solana",
      description:
        "A permissionless trust layer that scores autonomous agents on Solana — computed by an independent oracle cluster, threshold-signed, and anchored on-chain.",
      offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
    },
  ],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="grain min-h-screen bg-ink-0 text-ink-12 antialiased">
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
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
