import type { MetadataRoute } from "next";

const BASE = "https://phylanx.com";

/**
 * sitemap.xml — the canonical, crawlable surface of the site.
 * Static marketing/product routes only; the dynamic `/agent/[wallet]`
 * space is excluded (unbounded, user-supplied).
 */
export default function sitemap(): MetadataRoute.Sitemap {
  const now = new Date();
  const routes: Array<{
    path: string;
    priority: number;
    changeFrequency: MetadataRoute.Sitemap[number]["changeFrequency"];
  }> = [
    { path: "/",             priority: 1.0, changeFrequency: "weekly" },
    { path: "/docs",         priority: 0.9, changeFrequency: "weekly" },
    { path: "/network",      priority: 0.8, changeFrequency: "hourly" },
    { path: "/transparency", priority: 0.7, changeFrequency: "daily" },
    { path: "/taxonomy",     priority: 0.6, changeFrequency: "monthly" },
  ];

  return routes.map((r) => ({
    url: `${BASE}${r.path === "/" ? "" : r.path}`,
    lastModified: now,
    changeFrequency: r.changeFrequency,
    priority: r.priority,
  }));
}
