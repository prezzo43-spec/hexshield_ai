// =============================================================================
// HexShield AI — Root Page
// Redirects to the dashboard.
// =============================================================================

import { redirect } from "next/navigation";

export default function RootPage() {
  redirect("/dashboard");
}