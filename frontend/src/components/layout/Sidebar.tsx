// =============================================================================
// HexShield AI — Sidebar Navigation Component
// =============================================================================

"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Shield,
  LayoutDashboard,
  FolderOpen,
  Upload,
  Cpu,
  FileText,
  Users,
  Activity,
} from "lucide-react";

const NAV_ITEMS = [
  {
    label: "Dashboard",
    href: "/dashboard",
    icon: LayoutDashboard,
  },
  {
    label: "Cases",
    href: "/dashboard/cases",
    icon: FolderOpen,
  },
  {
    label: "Submit Evidence",
    href: "/dashboard/submit",
    icon: Upload,
  },
  {
    label: "Analysis",
    href: "/dashboard/analysis",
    icon: Cpu,
  },
  {
    label: "Reports",
    href: "/dashboard/reports",
    icon: FileText,
  },
  {
    label: "Investigators",
    href: "/dashboard/investigators",
    icon: Users,
  },
  {
    label: "System Health",
    href: "/dashboard/health",
    icon: Activity,
  },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside
      style={{
        width: "var(--sidebar-width)",
        minHeight: "100vh",
        background: "var(--card)",
        borderRight: "1px solid var(--card-border)",
        display: "flex",
        flexDirection: "column",
        position: "fixed",
        top: 0,
        left: 0,
        zIndex: 50,
      }}
    >
      {/* Logo */}
      <div
        style={{
          padding: "1.5rem 1.25rem",
          borderBottom: "1px solid var(--card-border)",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "0.75rem",
          }}
        >
          <div
            style={{
              width: 36,
              height: 36,
              background: "var(--primary)",
              borderRadius: 8,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <Shield size={20} color="white" />
          </div>
          <div>
            <div
              style={{
                fontWeight: 700,
                fontSize: "0.9375rem",
                color: "var(--foreground)",
                lineHeight: 1.2,
              }}
            >
              HexShield AI
            </div>
            <div
              style={{
                fontSize: "0.6875rem",
                color: "var(--muted)",
                marginTop: 2,
              }}
            >
              Forensic Platform v1.0.0
            </div>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav
        style={{
          flex: 1,
          padding: "1rem 0.75rem",
          display: "flex",
          flexDirection: "column",
          gap: "0.25rem",
        }}
      >
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive =
            item.href === "/dashboard"
              ? pathname === "/dashboard"
              : pathname.startsWith(item.href);

          return (
            <Link
              key={item.href}
              href={item.href}
              className={`sidebar-link ${isActive ? "active" : ""}`}
            >
              <Icon size={18} />
              {item.label}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div
        style={{
          padding: "1rem 1.25rem",
          borderTop: "1px solid var(--card-border)",
          fontSize: "0.75rem",
          color: "var(--muted)",
        }}
      >
        <div>ISO/IEC 27037 Compliant</div>
        <div style={{ marginTop: 2 }}>Republic of Kenya</div>
      </div>
    </aside>
  );
}