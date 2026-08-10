"use client";

import { motion } from "framer-motion";
import SolarplexLogo from "@/components/SolarplexLogo";

interface Props {
  /** Logo pixel size. Defaults to a size legible in a bounded content area. */
  size?: number;
  /** Optional caption below the mark, e.g. "Loading artifact…". */
  label?: string;
  className?: string;
}

// Branded stand-in for the generic bare-ring `animate-spin` div used across
// loading states (invite preview, artifact drawer/tab). Framer Motion's
// rotate picks up MotionConfig's reducedMotion="user" in app/providers.tsx
// automatically — no separate reduced-motion handling needed here.
export default function LoadingSpinner({ size = 28, label, className = "" }: Props) {
  return (
    <div className={`flex flex-col items-center justify-center gap-3 text-muted ${className}`}>
      <motion.div
        animate={{ rotate: 360 }}
        transition={{ duration: 1.4, repeat: Infinity, ease: "linear" }}
      >
        <SolarplexLogo size={size} className="opacity-80" />
      </motion.div>
      {label && <span className="text-xs">{label}</span>}
    </div>
  );
}
