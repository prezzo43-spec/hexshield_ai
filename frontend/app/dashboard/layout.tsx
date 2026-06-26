// =============================================================================
// HexShield AI — Dashboard Layout
// Wraps all dashboard pages with the sidebar navigation.
// =============================================================================

import Sidebar from "@/components/layout/Sidebar";

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
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