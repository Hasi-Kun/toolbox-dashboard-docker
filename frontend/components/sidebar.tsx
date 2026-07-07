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
  Sparkles,
  ChevronsLeft,
  ChevronsRight,
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

const COLLAPSE_STORAGE_KEY = "toolbox-sidebar-collapsed";

export function Sidebar() {
  const pathname = usePathname();
  const { t } = useLanguage();
  const [isAdmin, setIsAdmin] = useState(false);
  const [canInvite, setCanInvite] = useState(false);
  const [isPremium, setIsPremium] = useState(false);
  const [collapsed, setCollapsed] = useState(false);

  useEffect(() => {
    const stored = window.localStorage.getItem(COLLAPSE_STORAGE_KEY);
    if (stored === "true") setCollapsed(true);
  }, []);

  function toggleCollapsed() {
    setCollapsed((prev) => {
      const next = !prev;
      window.localStorage.setItem(COLLAPSE_STORAGE_KEY, String(next));
      return next;
    });
  }

  useEffect(() => {
    fetch("/api/auth/me")
      .then((res) => (res.ok ? res.json() : null))
      .then((me: { role?: string; invite_quota?: number; is_premium?: boolean } | null) => {
        setIsAdmin(me?.role === "admin");
        setCanInvite((me?.invite_quota ?? 0) > 0);
        setIsPremium(Boolean(me?.is_premium));
      })
      .catch(() => {
        setIsAdmin(false);
        setCanInvite(false);
        setIsPremium(false);
      });
  }, []);

  return (
    <aside
      className={cn(
        "hidden shrink-0 border-r border-base-border bg-base-elevated/60 md:flex md:flex-col transition-[width] duration-200",
        collapsed ? "w-16" : "w-64"
      )}
    >
      <div className="flex h-16 items-center justify-between gap-2 border-b border-base-border px-3">
        <div className={cn("flex items-center gap-2 overflow-hidden", collapsed && "justify-center")}>
          <Radar className="h-5 w-5 shrink-0 text-signal" strokeWidth={2.5} />
          {!collapsed && <span className="font-display text-lg tracking-tight text-ink">toolbox</span>}
        </div>
        {!collapsed && (
          <button
            type="button"
            onClick={toggleCollapsed}
            title="Sidebar einklappen"
            className="rounded-lg p-1.5 text-ink-muted hover:bg-base-border/60 hover:text-ink"
          >
            <ChevronsLeft className="h-4 w-4" />
          </button>
        )}
      </div>

      {collapsed && (
        <button
          type="button"
          onClick={toggleCollapsed}
          title="Sidebar ausklappen"
          className="flex items-center justify-center border-b border-base-border py-2 text-ink-muted hover:bg-base-border/60 hover:text-ink"
        >
          <ChevronsRight className="h-4 w-4" />
        </button>
      )}

      <nav className="flex-1 overflow-y-auto px-3 py-4">
        <SidebarLink href="/" icon={LayoutDashboard} label={t("sidebar.dashboard")} active={pathname === "/"} collapsed={collapsed} />
        <SidebarLink
          href="/feature-requests"
          icon={Lightbulb}
          label={t("sidebar.feature_requests")}
          active={pathname.startsWith("/feature-requests")}
          collapsed={collapsed}
        />

        {!collapsed && (
          <p className="mt-6 px-3 text-xs font-medium uppercase tracking-wider text-ink-muted">
            {t("sidebar.categories")}
          </p>
        )}
        <ul className={cn("space-y-0.5", collapsed ? "mt-4" : "mt-2")}>
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
                  collapsed={collapsed}
                />
              </li>
            );
          })}
        </ul>

        {!collapsed && (
          <p className="mt-6 px-3 text-xs font-medium uppercase tracking-wider text-ink-muted">
            {t("sidebar.admin")}
          </p>
        )}
        <ul className={cn("space-y-0.5", collapsed ? "mt-4" : "mt-2")}>
          {isAdmin && (
            <li>
              <SidebarLink href="/settings/users" icon={Users} label={t("sidebar.users")} active={pathname === "/settings/users"} collapsed={collapsed} />
            </li>
          )}
          {isAdmin && (
            <li>
              <SidebarLink href="/settings/audit-log" icon={ScrollText} label="Audit-Log" active={pathname === "/settings/audit-log"} collapsed={collapsed} />
            </li>
          )}
          {(isAdmin || canInvite) && (
            <li>
              <SidebarLink href="/settings/invites" icon={UserPlus} label={t("sidebar.invites")} active={pathname === "/settings/invites"} collapsed={collapsed} />
            </li>
          )}
          <li>
            <SidebarLink href="/settings/security" icon={Lock} label={t("sidebar.security")} active={pathname === "/settings/security"} collapsed={collapsed} />
          </li>
          {isPremium && (
            <li>
              <SidebarLink href="/settings/display-style" icon={Sparkles} label="Anzeigename-Style" active={pathname === "/settings/display-style"} collapsed={collapsed} />
            </li>
          )}
          {isAdmin && (
            <li>
              <SidebarLink
                href="/settings/appearance"
                icon={Palette}
                label={t("sidebar.appearance")}
                active={pathname === "/settings/appearance"}
                collapsed={collapsed}
              />
            </li>
          )}
        </ul>
      </nav>

      {!collapsed && (
        <div className="border-t border-base-border px-5 py-4 text-xs text-ink-muted">
          toolbox.hasikun.cc
        </div>
      )}
    </aside>
  );
}

function SidebarLink({
  href,
  icon: Icon,
  label,
  active,
  badge,
  collapsed,
}: {
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  active?: boolean;
  badge?: number;
  collapsed?: boolean;
}) {
  return (
    <Link
      href={href}
      title={collapsed ? label : undefined}
      className={cn(
        "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
        collapsed && "justify-center px-0",
        active
          ? "bg-signal/10 text-signal"
          : "text-ink-muted hover:bg-base-border/60 hover:text-ink"
      )}
    >
      <Icon className="h-4 w-4 shrink-0" />
      {!collapsed && <span className="flex-1 truncate">{label}</span>}
      {!collapsed && typeof badge === "number" && (
        <span className="rounded-full bg-base-border px-1.5 py-0.5 text-[10px] tabular-nums text-ink-muted">
          {badge}
        </span>
      )}
    </Link>
  );
}
