"use client";

import { useEffect } from "react";

/**
 * Blockiert das native Browser-Kontextmenue (Rechtsklick) app-weit,
 * mit gezielten Ausnahmen dort, wo es tatsaechlich gebraucht wird:
 *
 * - Eingabefelder (<input>, <textarea>) -- sonst waere Rechtsklick-
 *   Einfuegen (Paste) und die native Rechtschreibpruefung nicht mehr
 *   nutzbar, das waere fuer ein Formular-lastiges Tool nicht akzeptabel.
 * - contentEditable-Elemente (aus demselben Grund).
 * - Alles, was explizit ueber ein data-allow-context-menu-Attribut
 *   (auf dem Element selbst oder einem Vorfahren) opt-in macht -- z.B.
 *   Tool-Ergebnis-Ausgaben (zum Kopieren einzelner Werte) oder die
 *   WebCLI/Terminal-Ausgabe.
 *
 * Bewusst als eigene, global im Root-Layout eingebundene Komponente
 * statt verstreuter onContextMenu-Handler pro Seite -- ein einziger
 * Listener auf document, EINMAL definiert, gilt ueberall (inkl.
 * Login/Registrierung).
 */
export function ContextMenuGuard() {
  useEffect(() => {
    function handleContextMenu(event: MouseEvent) {
      const target = event.target as HTMLElement | null;
      if (!target) return;

      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA") return;
      if (target.isContentEditable) return;
      if (target.closest("[data-allow-context-menu]")) return;

      event.preventDefault();
    }

    document.addEventListener("contextmenu", handleContextMenu);
    return () => document.removeEventListener("contextmenu", handleContextMenu);
  }, []);

  return null;
}
