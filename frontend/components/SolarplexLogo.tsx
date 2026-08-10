/**
 * Solarplex logo mark — inline SVG, transparent background.
 *
 * All defs use an `sp-` prefix so IDs don't collide if the mark
 * is mounted more than once on the same page (AppNav + StatusPanel).
 * Since both instances reference identical gradients by the same IDs,
 * the browser uses whichever definition is parsed first — visually
 * identical on both sides.
 */

interface Props {
  size?: number;
  className?: string;
}

// Render all 24 sunburst rays for one half.
// `fill` must be a string like "url(#sp-indigoWash1)".
function SunRays({ fill }: { fill: string }) {
  return (
    <>
      {Array.from({ length: 24 }, (_, i) => (
        <path
          key={i}
          d="M 250 40 L 230 170 Q 250 210 270 170 Z"
          transform={`rotate(${i * 15} 250 250)`}
          fill={fill}
        />
      ))}
    </>
  );
}

export default function SolarplexLogo({ size = 26, className }: Props) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 500 500"
      width={size}
      height={size}
      className={className}
      aria-hidden
    >
      <defs>
        {/* ── Gradient pair: lighter half ─────────────────────────── */}
        <linearGradient id="sp-indigoWash1" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%"   stopColor="#b0bec5" stopOpacity="0.1" />
          <stop offset="30%"  stopColor="#9fa8da" stopOpacity="0.8" />
          <stop offset="100%" stopColor="#5c6bc0" stopOpacity="1"   />
        </linearGradient>
        <radialGradient id="sp-centerGrad1" cx="30%" cy="30%" r="70%">
          <stop offset="0%"   stopColor="#c5cae9" stopOpacity="0.9" />
          <stop offset="60%"  stopColor="#5c6bc0" stopOpacity="0.8" />
          <stop offset="100%" stopColor="#3949ab" stopOpacity="0.9" />
        </radialGradient>

        {/* ── Gradient pair: deeper half ───────────────────────────── */}
        <linearGradient id="sp-indigoWash2" x1="100%" y1="100%" x2="0%" y2="0%">
          <stop offset="0%"   stopColor="#7986cb" stopOpacity="0.9" />
          <stop offset="50%"  stopColor="#5c6bc0" stopOpacity="0.8" />
          <stop offset="100%" stopColor="#3949ab" stopOpacity="1"   />
        </linearGradient>
        <radialGradient id="sp-centerGrad2" cx="70%" cy="70%" r="70%">
          <stop offset="0%"   stopColor="#7986cb" stopOpacity="0.9" />
          <stop offset="60%"  stopColor="#3d5afe" stopOpacity="0.8" />
          <stop offset="100%" stopColor="#1a237e" stopOpacity="0.9" />
        </radialGradient>

        {/* ── Depth shadow on offset half ──────────────────────────── */}
        <filter id="sp-shadow" x="-50%" y="-50%" width="200%" height="200%">
          <feDropShadow dx="10" dy="10" stdDeviation="8"
            floodColor="#1a237e" floodOpacity="0.25" />
        </filter>

        {/* ── Diagonal clip paths ──────────────────────────────────── */}
        {/* Upper-left triangle (stationary lighter half) */}
        <clipPath id="sp-topRightHalf">
          <path d="M0,0 L500,500 L0,500 Z" />
        </clipPath>
        {/* Lower-right triangle (offset deeper half) */}
        <clipPath id="sp-bottomLeftHalf">
          <path d="M0,0 L0,500 L500,500 Z" />
        </clipPath>
      </defs>

      {/* ── Lighter half — stationary ────────────────────────────── */}
      <g clipPath="url(#sp-topRightHalf)">
        <SunRays fill="url(#sp-indigoWash1)" />
        <circle cx="250" cy="250" r="110" fill="url(#sp-centerGrad1)" />
        <circle cx="250" cy="250" r="130" fill="none"
          stroke="#8c9eff" strokeWidth="2" opacity="0.6" strokeDasharray="4 8" />
        <circle cx="250" cy="250" r="220" fill="none"
          stroke="url(#sp-indigoWash1)" strokeWidth="6" strokeDasharray="12 18" />
        <circle cx="250" cy="250" r="240" fill="none"
          stroke="url(#sp-indigoWash1)" strokeWidth="3" strokeDasharray="6 24" opacity="0.5" />
      </g>

      {/* ── Deeper half — offset + shadow (the "slice" effect) ───── */}
      <g clipPath="url(#sp-bottomLeftHalf)">
        <g transform="translate(15, 15)" filter="url(#sp-shadow)">
          <SunRays fill="url(#sp-indigoWash2)" />
          <circle cx="250" cy="250" r="110" fill="url(#sp-centerGrad2)" />
          <circle cx="250" cy="250" r="130" fill="none"
            stroke="#536dfe" strokeWidth="2" opacity="0.6" strokeDasharray="4 8" />
          <circle cx="250" cy="250" r="220" fill="none"
            stroke="url(#sp-indigoWash2)" strokeWidth="6" strokeDasharray="12 18" />
          <circle cx="250" cy="250" r="240" fill="none"
            stroke="url(#sp-indigoWash2)" strokeWidth="3" strokeDasharray="6 24" opacity="0.5" />
        </g>
      </g>
    </svg>
  );
}
