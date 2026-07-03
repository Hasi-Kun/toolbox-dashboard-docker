"use client";

import { useEffect, useRef } from "react";

export type BackgroundStyle = "none" | "dots" | "gradient" | "starfield" | "custom";

export interface AnimatedBackgroundProps {
  style: BackgroundStyle;
  customUrl?: string | null;
  /** 0.25 (sehr langsam) bis 3 (sehr schnell), 1 = Standard */
  speed?: number;
  /** Hex-Farbe fuer den Gradient-Stil */
  gradientColor?: string;
  /** Nur fuer "dots": Partikel reagieren auf Mausbewegung */
  interactive?: boolean;
  /** Skaliert den Effekt auf den Elternconainer statt auf den Viewport
   * (fuer die Live-Vorschau in den Einstellungen). */
  contained?: boolean;
}

export function AnimatedBackground({
  style,
  customUrl,
  speed = 1,
  gradientColor = "#35E0C0",
  interactive = true,
  contained = false,
}: AnimatedBackgroundProps) {
  if (style === "none") return null;
  const positionClass = contained ? "absolute inset-0" : "fixed inset-0";

  if (style === "custom" && customUrl) {
    return (
      <div
        className={`${positionClass} -z-10 bg-cover bg-center opacity-40`}
        style={{ backgroundImage: `url(${customUrl})` }}
        aria-hidden="true"
      />
    );
  }

  if (style === "gradient") {
    const duration = Math.max(1, 8 / speed);
    return (
      <div
        className={`${positionClass} -z-10 animate-gradient-pulse`}
        style={{
          background: `radial-gradient(ellipse at 30% 20%, ${hexToRgba(gradientColor, 0.16)}, transparent 55%), radial-gradient(ellipse at 80% 80%, ${hexToRgba(gradientColor, 0.1)}, transparent 55%)`,
          animationDuration: `${duration}s`,
        }}
        aria-hidden="true"
      />
    );
  }

  if (style === "starfield") {
    return (
      <div className={`${positionClass} -z-10 bg-black`} aria-hidden="true">
        <Particles mode="starfield" speed={speed} interactive={false} contained={contained} />
      </div>
    );
  }

  return <Particles mode="dots" speed={speed} interactive={interactive} contained={contained} />;
}

function hexToRgba(hex: string, alpha: number): string {
  const clean = hex.replace("#", "");
  const r = parseInt(clean.substring(0, 2), 16) || 0;
  const g = parseInt(clean.substring(2, 4), 16) || 0;
  const b = parseInt(clean.substring(4, 6), 16) || 0;
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

/** Gemeinsame Canvas-Partikel-Engine fuer "Connecting Dots" (teal, mit
 * Verbindungslinien + Mausinteraktion) und "Sternenhimmel" (weiss/blau,
 * langsames Funkeln, keine Linien, kein Maus-Tracking noetig). */
function Particles({
  mode,
  speed,
  interactive,
  contained,
}: {
  mode: "dots" | "starfield";
  speed: number;
  interactive: boolean;
  contained: boolean;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext("2d");
    if (!canvas || !ctx) return;

    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    const getSize = (): [number, number] =>
      contained
        ? [canvas.parentElement?.clientWidth ?? 300, canvas.parentElement?.clientHeight ?? 200]
        : [window.innerWidth, window.innerHeight];

    let [width, height] = getSize();
    canvas.width = width;
    canvas.height = height;

    const isStarfield = mode === "starfield";
    const COUNT = isStarfield
      ? Math.min(160, Math.max(60, Math.floor((width * height) / 9000)))
      : Math.min(90, Math.max(30, Math.floor((width * height) / 16000)));
    const MAX_DIST = 140;
    const baseVelocity = isStarfield ? 0.06 : 0.25;

    const particles = Array.from({ length: COUNT }, () => ({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * baseVelocity,
      vy: (Math.random() - 0.5) * baseVelocity,
      // fuer den Sternenhimmel: individuelle Funkel-Phase
      phase: Math.random() * Math.PI * 2,
      twinkleSpeed: 0.3 + Math.random() * 0.7,
      radius: isStarfield ? 0.5 + Math.random() * 1.2 : 1.5,
    }));

    const mouse = { x: -9999, y: -9999, active: false };

    function handlePointerMove(e: PointerEvent) {
      const rect = canvas!.getBoundingClientRect();
      mouse.x = e.clientX - rect.left;
      mouse.y = e.clientY - rect.top;
      mouse.active = true;
    }
    function handlePointerLeave() {
      mouse.active = false;
    }

    if (mode === "dots" && interactive) {
      const target = contained ? canvas : window;
      target.addEventListener("pointermove", handlePointerMove as EventListener);
      canvas.addEventListener("pointerleave", handlePointerLeave);
    }

    function resize() {
      [width, height] = getSize();
      canvas!.width = width;
      canvas!.height = height;
    }
    window.addEventListener("resize", resize);

    let animationFrame: number;
    let t = 0;

    function draw() {
      ctx!.clearRect(0, 0, width, height);

      if (mode === "dots") {
        for (let i = 0; i < particles.length; i++) {
          for (let j = i + 1; j < particles.length; j++) {
            const dx = particles[i].x - particles[j].x;
            const dy = particles[i].y - particles[j].y;
            const dist = Math.sqrt(dx * dx + dy * dy);
            if (dist < MAX_DIST) {
              ctx!.strokeStyle = `rgba(53, 224, 192, ${(1 - dist / MAX_DIST) * 0.15})`;
              ctx!.lineWidth = 1;
              ctx!.beginPath();
              ctx!.moveTo(particles[i].x, particles[i].y);
              ctx!.lineTo(particles[j].x, particles[j].y);
              ctx!.stroke();
            }
          }

          if (mouse.active) {
            const dx = particles[i].x - mouse.x;
            const dy = particles[i].y - mouse.y;
            const dist = Math.sqrt(dx * dx + dy * dy);
            if (dist < MAX_DIST * 1.3) {
              ctx!.strokeStyle = `rgba(53, 224, 192, ${(1 - dist / (MAX_DIST * 1.3)) * 0.35})`;
              ctx!.lineWidth = 1;
              ctx!.beginPath();
              ctx!.moveTo(particles[i].x, particles[i].y);
              ctx!.lineTo(mouse.x, mouse.y);
              ctx!.stroke();
            }
          }
        }

        for (const p of particles) {
          ctx!.fillStyle = "rgba(53, 224, 192, 0.45)";
          ctx!.beginPath();
          ctx!.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
          ctx!.fill();
        }
      } else {
        // Sternenhimmel: kein Verbindungsnetz, dafuer sanftes Funkeln
        for (const p of particles) {
          const twinkle = 0.35 + 0.5 * (0.5 + 0.5 * Math.sin(t * p.twinkleSpeed + p.phase));
          ctx!.fillStyle = `rgba(220, 230, 255, ${twinkle})`;
          ctx!.beginPath();
          ctx!.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
          ctx!.fill();
        }
      }
    }

    function tick() {
      t += 0.02 * speed;
      for (const p of particles) {
        p.x += p.vx * speed;
        p.y += p.vy * speed;
        if (p.x <= 0 || p.x >= width) p.vx *= -1;
        if (p.y <= 0 || p.y >= height) p.vy *= -1;

        if (mode === "dots" && mouse.active) {
          const dx = p.x - mouse.x;
          const dy = p.y - mouse.y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 60 && dist > 0.01) {
            p.x += (dx / dist) * 0.6;
            p.y += (dy / dist) * 0.6;
          }
        }
      }
      draw();
      animationFrame = requestAnimationFrame(tick);
    }

    if (reduceMotion) {
      draw();
    } else {
      tick();
    }

    return () => {
      window.removeEventListener("resize", resize);
      if (mode === "dots" && interactive) {
        const target = contained ? canvas : window;
        target.removeEventListener("pointermove", handlePointerMove as EventListener);
        canvas.removeEventListener("pointerleave", handlePointerLeave);
      }
      if (animationFrame) cancelAnimationFrame(animationFrame);
    };
  }, [mode, speed, interactive, contained]);

  return <canvas ref={canvasRef} className={`${contained ? "absolute" : "fixed"} inset-0 -z-10`} aria-hidden="true" />;
}
