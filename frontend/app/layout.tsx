// =============================================================================
// HexShield AI — Root Layout
// =============================================================================

import type { Metadata } from "next";
import "./globals.css";

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
      <body>{children}</body>
    </html>
  );
}