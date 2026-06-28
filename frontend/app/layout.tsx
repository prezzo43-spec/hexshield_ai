// =============================================================================
// HexShield AI — Root Layout
// =============================================================================

import type { Metadata } from "next";
import "./globals.css";
import { AuthProvider } from "@/contexts/AuthContext";

export const metadata: Metadata = {
  title: "HexShield AI — Digital Forensic Platform",
  description:
    "A Multi-Layered Forensic Engine for Malicious Streams and Manipulated Media",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <AuthProvider>{children}</AuthProvider>
      </body>
    </html>
  );
}