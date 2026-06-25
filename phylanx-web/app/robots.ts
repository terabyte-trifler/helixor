import type { MetadataRoute } from "next";

const BASE = "https://phylanx.com";

/**
 * robots.txt — allow full crawl, point crawlers at the sitemap.
 * Per-wallet agent pages are crawlable but intentionally not listed in the
 * sitemap (they're an unbounded, user-supplied space).
 */
export default function robots(): MetadataRoute.Robots {
  return {
    rules: { userAgent: "*", allow: "/" },
    sitemap: `${BASE}/sitemap.xml`,
    host: BASE,
  };
}
