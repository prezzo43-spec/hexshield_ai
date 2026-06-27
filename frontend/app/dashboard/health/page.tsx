// =============================================================================
// HexShield AI — System Health Page
// =============================================================================

"use client";

import { useEffect, useState } from "react";
import {
  Activity,
  Database,
  Shield,
  Cpu,
  CheckCircle,
  AlertTriangle,
  RefreshCw,
} from "lucide-react";
import { checkDetailedHealth } from "@/services/api";
import { formatDate } from "@/types";

export default function HealthPage() {
  const [health, setHealth] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [lastChecked, setLastChecked] = useState<string>("");

  const fetchHealth = async () => {
    setLoading(true);
    try {
      const data = await checkDetailedHealth();
      setHealth(data);
      setLastChecked(new Date().toISOString());
    } catch (e) {
      setHealth(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  const ComponentCard = ({
    icon: Icon,
    name,
    status,
    detail,
    color,
  }: {
    icon: any;
    name: string;
    status: string;
    detail?: string;
    color: string;
  }) => (
    <div className="card">
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          marginBottom: "0.75rem",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
          <div
            style={{
              width: 40,
              height: 40,
              background: `${color}20`,
              borderRadius: 10,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <Icon size={20} color={color} />
          </div>
          <div>
            <div style={{ fontWeight: 600 }}>{name}</div>
            {detail && (
              <div style={{ fontSize: "0.75rem", color: "var(--muted)" }}>
                {detail}
              </div>
            )}
          </div>
        </div>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "0.375rem",
            fontSize: "0.875rem",
            fontWeight: 500,
            color:
              status === "healthy"
                ? "var(--success)"
                : status === "pending"
                ? "var(--warning)"
                : "var(--danger)",
          }}
        >
          {status === "healthy" ? (
            <CheckCircle size={16} />
          ) : (
            <AlertTriangle size={16} />
          )}
          {status.toUpperCase()}
        </div>
      </div>
    </div>
  );

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">System Health</h1>
          <p className="page-subtitle">
            Real-time status of all HexShield AI components
          </p>
        </div>
        <button
          className="btn btn-outline"
          onClick={fetchHealth}
          disabled={loading}
        >
          <RefreshCw size={16} className={loading ? "spin" : ""} />
          Refresh
        </button>
      </div>

      {lastChecked && (
        <p
          style={{
            fontSize: "0.8125rem",
            color: "var(--muted)",
            marginBottom: "1.5rem",
          }}
        >
          Last checked: {formatDate(lastChecked)}
        </p>
      )}

      {loading && !health ? (
        <div className="empty-state" style={{ height: "40vh" }}>
          <div className="loading-spinner" />
          Checking system health...
        </div>
      ) : !health ? (
        <div className="alert alert-error">
          <AlertTriangle size={16} style={{ flexShrink: 0 }} />
          Unable to reach the HexShield AI backend. Ensure the server is
          running at {process.env.NEXT_PUBLIC_API_URL}.
        </div>
      ) : (
        <>
          {/* Overall Status */}
          <div
            className={`alert ${
              health.status === "healthy" ? "alert-success" : "alert-warning"
            }`}
            style={{ marginBottom: "1.5rem", fontSize: "1rem" }}
          >
            <Activity size={18} style={{ flexShrink: 0 }} />
            <div>
              <strong>
                Overall System Status: {health.status.toUpperCase()}
              </strong>
              <div style={{ fontSize: "0.875rem", marginTop: 4 }}>
                {health.app} v{health.version} — {health.environment}{" "}
                environment
              </div>
            </div>
          </div>

          {/* Component Grid */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(2, 1fr)",
              gap: "1rem",
              marginBottom: "1.5rem",
            }}
          >
            <ComponentCard
              icon={Database}
              name="Neon PostgreSQL Database"
              status={health.components?.database?.status || "unknown"}
              detail="Primary forensic data store — Neon Serverless (London)"
              color="var(--primary)"
            />
            <ComponentCard
              icon={Shield}
              name="Hex Triage Engine"
              status={health.components?.hex_engine?.status || "unknown"}
              detail={`v${health.components?.hex_engine?.version || "1.0.0"} — Magic bytes, entropy, MIME spoofing`}
              color="var(--accent)"
            />
            <ComponentCard
              icon={Cpu}
              name="AI Deepfake Engine"
              status={health.components?.ai_engine?.status || "pending"}
              detail="Image, video, and audio manipulation detection"
              color="var(--secondary)"
            />
            <ComponentCard
              icon={Activity}
              name="FastAPI Backend"
              status="healthy"
              detail={`${health.app} v${health.version}`}
              color="var(--success)"
            />
          </div>

          {/* System Info */}
          <div className="card">
            <h2 className="section-title">System Information</h2>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(2, 1fr)",
                gap: "1rem",
              }}
            >
              <div>
                <div className="stat-label">Python Version</div>
                <div
                  style={{
                    fontFamily: "monospace",
                    fontSize: "0.875rem",
                    marginTop: 4,
                  }}
                >
                  {health.system?.python_version?.split(" ")[0] || "N/A"}
                </div>
              </div>
              <div>
                <div className="stat-label">Platform</div>
                <div
                  style={{
                    fontFamily: "monospace",
                    fontSize: "0.875rem",
                    marginTop: 4,
                  }}
                >
                  {health.system?.platform || "N/A"}
                </div>
              </div>
              <div>
                <div className="stat-label">Environment</div>
                <div style={{ fontSize: "0.875rem", marginTop: 4 }}>
                  {health.environment}
                </div>
              </div>
              <div>
                <div className="stat-label">Compliance</div>
                <div style={{ fontSize: "0.875rem", marginTop: 4 }}>
                  ISO/IEC 27037 — Republic of Kenya
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}