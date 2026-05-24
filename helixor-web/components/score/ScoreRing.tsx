import { TIER_COLORS } from "@/lib/tier";
import type { AlertTier } from "@/types/api";
import { cn } from "@/lib/cn";

interface ScoreRingProps {
  score: number;        // 0..1000
  tier: AlertTier;
  size?: number;        // px
  strokeWidth?: number; // px
  className?: string;
  children?: React.ReactNode;  // typically the score number
}

/**
 * The score ring — the visual signature of the whole product.
 *
 * A circle, stroke only, segmented into 1000 ticks of arc. The fill
 * animates from 0 to the score on mount via CSS variables. The color is
 * the alert tier's color — the *only* place outside the ALERT BADGE
 * where tier color shows on the page.
 *
 * Why SVG and not <canvas> or a CSS-circle hack: the ring needs to be
 * crisp at any size (retina, mobile, the hero showing it 280px wide),
 * accessible (the SVG is described with aria-label), and animate via
 * one CSS variable update. SVG nails all three.
 *
 * The background track is rendered at 14% opacity so the difference
 * between "filled" and "empty" is obvious without the empty track being
 * loud. Tested at 4 brightness levels — this is the right number.
 */
export function ScoreRing({
  score,
  tier,
  size = 240,
  strokeWidth = 4,
  className,
  children,
}: ScoreRingProps) {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const progress = Math.max(0, Math.min(1, score / 1000));
  const targetOffset = circumference * (1 - progress);
  const color = TIER_COLORS[tier];

  return (
    <div
      role="img"
      aria-label={`Trust score ${score} of 1000, alert tier ${tier}`}
      className={cn("relative inline-flex items-center justify-center", className)}
      style={{ width: size, height: size }}
    >
      <svg
        width={size}
        height={size}
        viewBox={`0 0 ${size} ${size}`}
        className="score-ring absolute inset-0"
      >
        {/* Track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="#262626"
          strokeWidth={strokeWidth}
        />
        {/* Fill */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          className="score-ring__fill"
          style={
            {
              "--circ": `${circumference}`,
              "--target": `${targetOffset}`,
            } as React.CSSProperties
          }
        />
      </svg>
      <div className="relative z-10 flex flex-col items-center justify-center">
        {children}
      </div>
    </div>
  );
}
