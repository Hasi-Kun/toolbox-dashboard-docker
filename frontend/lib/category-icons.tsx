import {
  Globe,
  Mail,
  Network,
  ScanLine,
  ShieldCheck,
  Gauge,
  ArrowRightLeft,
  FileKey,
  Eye,
  type LucideIcon,
} from "lucide-react";

/**
 * Zentrale Zuordnung Kategorie-Slug -> Icon. Ausgelagert aus sidebar.tsx,
 * damit das Dashboard (und ggf. weitere Stellen) dieselben Icons
 * wiederverwenden koennen, statt die Zuordnung zu duplizieren.
 *
 * "scanner" (frueher "nmap" + separates "testssl") nutzt ScanLine statt
 * des vorherigen Radar-Icons -- Radar bleibt bewusst dem App-eigenen
 * Logo vorbehalten (Sidebar-Kopf, Login-Seite), damit es nicht doppelt
 * fuer Logo UND eine einzelne Kategorie steht.
 */
export const categoryIconBySlug: Record<string, LucideIcon> = {
  dns: Globe,
  mail: Mail,
  network: Network,
  scanner: ScanLine,
  security: ShieldCheck,
  website: Gauge,
  converter: ArrowRightLeft,
  certificates: FileKey,
  osint: Eye,
};

export const DEFAULT_CATEGORY_ICON: LucideIcon = Globe;
