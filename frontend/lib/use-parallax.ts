"use client";

import { useEffect, useRef, useState } from "react";

export type ParallaxOffset = { x: number; y: number };

/**
 * Liefert eine auf -1..1 normalisierte Mausposition relativ zur
 * Bildschirmmitte -- fuer den Parallax-Effekt auf der Login-Seite.
 * Respektiert prefers-reduced-motion (dann bleibt der Offset bei 0/0).
 *
 * WICHTIG (Performance-Fix): "pointermove" kann auf vielen Systemen weit
 * haeufiger als die Bildwiederholrate feuern (100+ Hz je nach Maus-
 * Polling-Rate) -- ein React-State-Update pro Rohereignis hat vorher
 * bei JEDER Mausbewegung eine volle Re-Render- und Style-Neuberechnung
 * ausgeloest (per Firefox-Profiler bestaetigt: 408 neu gestartete CSS-
 * Transitions, 729 Style-Neuberechnungen, 410 komplette Display-List-
 * Rebuilds waehrend einer Login-Seiten-Sitzung). Die rohen Koordinaten
 * werden jetzt in einer Ref zwischengespeichert (loest KEINEN Render
 * aus) und nur einmal pro Animationsframe per requestAnimationFrame in
 * den tatsaechlichen State uebernommen -- maximal ~60 Updates/Sekunde
 * statt potenziell hunderte.
 */
export function useParallax(enabled: boolean): ParallaxOffset {
  const [offset, setOffset] = useState<ParallaxOffset>({ x: 0, y: 0 });
  const latestRef = useRef<ParallaxOffset>({ x: 0, y: 0 });
  const rafIdRef = useRef<number | null>(null);

  useEffect(() => {
    if (!enabled) {
      setOffset({ x: 0, y: 0 });
      return;
    }
    if (typeof window === "undefined") return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    function handlePointerMove(e: PointerEvent) {
      // Nur die Ref aktualisieren -- KEIN Render/State-Update hier, das
      // waere bei jedem einzelnen Rohereignis der teure Schritt.
      latestRef.current = {
        x: (e.clientX / window.innerWidth) * 2 - 1,
        y: (e.clientY / window.innerHeight) * 2 - 1,
      };
    }

    function tick() {
      setOffset((prev) => {
        const next = latestRef.current;
        // Keine neue Objekt-Referenz erzeugen, wenn sich effektiv nichts
        // geaendert hat -- vermeidet unnoetige Re-Renders im Stillstand.
        if (prev.x === next.x && prev.y === next.y) return prev;
        return next;
      });
      rafIdRef.current = requestAnimationFrame(tick);
    }

    window.addEventListener("pointermove", handlePointerMove, { passive: true });
    rafIdRef.current = requestAnimationFrame(tick);

    return () => {
      window.removeEventListener("pointermove", handlePointerMove);
      if (rafIdRef.current !== null) cancelAnimationFrame(rafIdRef.current);
    };
  }, [enabled]);

  return offset;
}
