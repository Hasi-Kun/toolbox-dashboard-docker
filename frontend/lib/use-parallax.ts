"use client";

import { useEffect, useState } from "react";

export type ParallaxOffset = { x: number; y: number };

/**
 * Liefert eine auf -1..1 normalisierte Mausposition relativ zur
 * Bildschirmmitte -- fuer den Parallax-Effekt auf der Login-Seite.
 * Respektiert prefers-reduced-motion (dann bleibt der Offset bei 0/0).
 */
export function useParallax(enabled: boolean): ParallaxOffset {
  const [offset, setOffset] = useState<ParallaxOffset>({ x: 0, y: 0 });

  useEffect(() => {
    if (!enabled) {
      setOffset({ x: 0, y: 0 });
      return;
    }
    if (typeof window === "undefined") return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    function handlePointerMove(e: PointerEvent) {
      const x = (e.clientX / window.innerWidth) * 2 - 1;
      const y = (e.clientY / window.innerHeight) * 2 - 1;
      setOffset({ x, y });
    }

    window.addEventListener("pointermove", handlePointerMove);
    return () => window.removeEventListener("pointermove", handlePointerMove);
  }, [enabled]);

  return offset;
}
