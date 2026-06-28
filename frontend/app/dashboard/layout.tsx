// =============================================================================
// HexShield AI — Dashboard Layout
// Protects all dashboard routes — redirects to login if not authenticated.
// =============================================================================

"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/contexts/AuthContext";
import Sidebar from "@/components/layout/Sidebar";

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const { investigator, loading, isAuthenticated } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (loading) return;

    if (!isAuthenticated) {
      router.push("/login");
      return;
    }

    if (investigator?.first_login) {
      router.push("/change-password");
      return;
    }
  }, [loading, isAuthenticated, investigator, router]);

  if (loading) {
    return (
      <div
        style={{
          minHeight: "100vh",
          background: "var(--background)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          gap: "1rem",
          color: "var(--muted)",
          fontSize: "0.875rem",
        }}
      >
        <div className="loading-spinner" />
        Verifying session...
      </div>
    );
  }

  if (!isAuthenticated) {
    return null;
  }

  return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      <Sidebar />
      <main
        style={{
          marginLeft: "var(--sidebar-width)",
          flex: 1,
          padding: "2rem",
          minHeight: "100vh",
          background: "var(--background)",
        }}
      >
        {children}
      </main>
    </div>
  );
}