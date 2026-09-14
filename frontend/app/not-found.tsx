"use client";

import Link from "next/link";
import { ArrowLeft, FolderOpen, Home } from "lucide-react";

export default function NotFound() {
  return (
    <main
      style={{
        minHeight: "100vh",
        display: "grid",
        placeItems: "center",
        padding: "2rem",
        background: "var(--background)",
      }}
    >
      <section className="card" style={{ maxWidth: 560, textAlign: "center" }}>
        <div
          style={{
            color: "var(--primary)",
            fontSize: "4rem",
            fontWeight: 800,
            lineHeight: 1,
            marginBottom: "1rem",
          }}
        >
          404
        </div>
        <h1 className="section-title">Page not found</h1>
        <p style={{ color: "var(--muted)", marginBottom: "1.5rem" }}>
          The requested forensic workspace page does not exist or is no longer available.
        </p>
        <div style={{ display: "flex", justifyContent: "center", gap: "0.75rem", flexWrap: "wrap" }}>
          <Link href="/dashboard" className="btn btn-primary">
            <Home size={16} />
            Dashboard
          </Link>
          <Link href="/dashboard/cases" className="btn btn-outline">
            <FolderOpen size={16} />
            Cases
          </Link>
          <button className="btn btn-outline" onClick={() => window.history.back()}>
            <ArrowLeft size={16} />
            Go Back
          </button>
        </div>
      </section>
    </main>
  );
}
