"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Globe,
  Mail,
  Network,
  Radar,
  ShieldCheck,
  Gauge,
  Wrench,
  FileKey,
  LayoutDashboard,
  Users,
  Lock,
  Palette,
  Lightbulb,
  UserPlus,
  ScrollText,
  Eye,
} from "lucide-react";
import { categories } from "@/lib/categories";
import { cn } from "@/lib/utils";
import { useLanguage } from "@/components/language-provider";
import type { TranslationKey } from "@/lib/i18n";

const iconBySlug: Record<string, React.ComponentType<{ className?: string }>> = {
  dns: Globe,
  mail: Mail,
  network: Network,
  nmap: Radar,
  security: ShieldCheck,
  website: Gauge,
  utilities: Wrench,
  certificates: FileKey,
  osint: Eye,
};

export function Sidebar() {
  const pathname = usePathname();
  const { t } = useLanguage();
  const [isAdmin, setIsAdmin] = useState(false);
  const [canInvite, setCanInvite] = useState(false);

  useEffect(() => {
    fetch("/api/auth/me")
      .then((res) => (res.ok ? res.json() : null))
      .then((me: { role?: string; can_invite?: boolean } | null) => {
        setIsAdmin(me?.role === "admin");
        setCanInvite(Boolean(me?.can_invite));
      })
      .catch(() => {
        setIsAdmin(false);
        setCanInvite(false);
      });
  }, []);

  return (
    <aside className="hidden w-64 shrink-0 border-r border-base-border bg-base-elevated/60 md:flex md:flex-col">
      <div className="flex h-16 items-center gap-2 border-b border-base-border px-5">
        <Radar className="h-5 w-5 text-signal" strokeWidth={2.5} />
        <span className="font-display text-lg tracking-tight text-ink">toolbox</span>
      </div>

      <nav className="flex-1 overflow-y-auto px-3 py-4">
        <SidebarLink href="/" icon={LayoutDashboard} label={t("sidebar.dashboard")} active={pathname === "/"} />
        <SidebarLink
          href="/feature-requests"
          icon={Lightbulb}
          label={t("sidebar.feature_requests")}
          active={pathname.startsWith("/feature-requests")}
        />

        <p className="mt-6 px-3 text-xs font-medium uppercase tracking-wider text-ink-muted">
          {t("sidebar.categories")}
        </p>
        <ul className="mt-2 space-y-0.5">
          {categories.map((category) => {
            const Icon = iconBySlug[category.slug] ?? Globe;
            const href = `/category/${category.slug}`;
            const nameKey = `categories.${category.slug}.name` as TranslationKey;
            return (
              <li key={category.slug}>
                <SidebarLink
                  href={href}
                  icon={Icon}
                  label={t(nameKey) !== nameKey ? t(nameKey) : category.name}
                  badge={category.toolCount}
                  active={pathname === href}
                />
              </li>
            );
          })}
        </ul>

        <p className="mt-6 px-3 text-xs font-medium uppercase tracking-wider text-ink-muted">
          {t("sidebar.admin")}
        </p>
        <ul className="mt-2 space-y-0.5">
          {isAdmin && (
            <li>
              <SidebarLink href="/settings/users" icon={Users} label={t("sidebar.users")} active={pathname === "/settings/users"} />
            </li>
          )}
          {isAdmin && (
            <li>
              <SidebarLink href="/settings/audit-log" icon={ScrollText} label="Audit-Log" active={pathname === "/settings/audit-log"} />
            </li>
          )}
          {(isAdmin || canInvite) && (
            <li>
              <SidebarLink href="/settings/invites" icon={UserPlus} label={t("sidebar.invites")} active={pathname === "/settings/invites"} />
            </li>
          )}
          <li>
            <SidebarLink href="/settings/security" icon={Lock} label={t("sidebar.security")} active={pathname === "/settings/security"} />
          </li>
          {isAdmin && (
            <li>
              <SidebarLink
                href="/settings/appearance"
                icon={Palette}
                label={t("sidebar.appearance")}
                active={pathname === "/settings/appearance"}
              />
            </li>
          )}
        </ul>
      </nav>

      <div className="border-t border-base-border px-5 py-4 text-xs text-ink-muted">
        {{TOOLBOX_DOMAIN}}
      </div>
    </aside>
  );
}

function SidebarLink({
  href,
  icon: Icon,
  label,
  active,
  badge,
}: {
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  active?: boolean;
  badge?: number;
}) {
  return (
    <Link
      href={href}
      className={cn(
        "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
        active
          ? "bg-signal/10 text-signal"
          : "text-ink-muted hover:bg-base-border/60 hover:text-ink"
      )}
    >
      <Icon className="h-4 w-4 shrink-0" />
      <span className="flex-1 truncate">{label}</span>
      {typeof badge === "number" && (
        <span className="rounded-full bg-base-border px-1.5 py-0.5 text-[10px] tabular-nums text-ink-muted">
          {badge}
        </span>
      )}
    </Link>
  );
}
