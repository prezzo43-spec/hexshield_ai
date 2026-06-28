// =============================================================================
// HexShield AI — Root Page
// Redirects to dashboard if authenticated, otherwise to login.
// =============================================================================

"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/contexts/AuthContext";

export default function RootPage() {
  const { isAuthenticated, loading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (loading) return;
    if (isAuthenticated) {
      router.push("/dashboard");
    } else {
      router.push("/login");
    }
  }, [loading, isAuthenticated, router]);

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
      Loading HexShield AI...
    </div>
  );
}