"use client";

import { useEffect, useRef, useState } from "react";

/**
 * Animiert eine Zahl von 0 (bzw. vom vorherigen Wert) zum Zielwert hoch --
 * fuer die "Count-up"-Zahlen auf den Dashboard-Statuskarten. Respektiert
 * prefers-reduced-motion (springt dann direkt zum Zielwert).
 */
export function useCountUp(target: number, durationMs = 700): number {
  const [value, setValue] = useState(0);
  const startRef = useRef<number | null>(null);
  const fromRef = useRef(0);

  useEffect(() => {
    if (typeof window === "undefined") {
      setValue(target);
      return;
    }
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      setValue(target);
      return;
    }

    fromRef.current = value;
    startRef.current = null;
    let frame: number;

    function tick(timestamp: number) {
      if (startRef.current === null) startRef.current = timestamp;
      const elapsed = timestamp - startRef.current;
      const progress = Math.min(1, elapsed / durationMs);
      // easeOutCubic -- schnell los, sanft einschwingen
      const eased = 1 - Math.pow(1 - progress, 3);
      setValue(fromRef.current + (target - fromRef.current) * eased);
      if (progress < 1) frame = requestAnimationFrame(tick);
    }

    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target, durationMs]);

  return value;
}
