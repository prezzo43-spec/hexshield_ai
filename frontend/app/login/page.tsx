// =============================================================================
// HexShield AI — Login Page
// =============================================================================

"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Shield, Eye, EyeOff, AlertTriangle, Lock } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";

export default function LoginPage() {
  const router = useRouter();
  const { login } = useAuth();

  const [loginIdentifier, setLoginIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleLogin = async () => {
    setError("");

    if (!loginIdentifier || !password) {
      setError("Badge number/email and password are required.");
      return;
    }

    setLoading(true);
    try {
      await login(loginIdentifier, password);
      router.push("/dashboard");
    } catch (e: any) {
      setError(
        e?.response?.data?.detail ||
          "Login failed. Please check your credentials."
      );
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") handleLogin();
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "var(--background)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: "1.5rem",
      }}
    >
      <div style={{ width: "100%", maxWidth: 440 }}>
        {/* Logo */}
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            marginBottom: "2rem",
          }}
        >
          <div
            style={{
              width: 64,
              height: 64,
              background: "var(--primary)",
              borderRadius: 16,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              marginBottom: "1rem",
              boxShadow: "0 0 32px rgba(59,130,246,0.3)",
            }}
          >
            <Shield size={32} color="white" />
          </div>
          <h1
            style={{
              fontSize: "1.75rem",
              fontWeight: 800,
              color: "var(--foreground)",
              letterSpacing: "-0.025em",
            }}
          >
            HexShield AI
          </h1>
          <p
            style={{
              fontSize: "0.875rem",
              color: "var(--muted)",
              marginTop: "0.25rem",
              textAlign: "center",
            }}
          >
            Digital Forensic Platform
          </p>
          <p
            style={{
              fontSize: "0.75rem",
              color: "var(--muted)",
              marginTop: "0.25rem",
            }}
          >
            Republic of Kenya — ISO/IEC 27037 Compliant
          </p>
        </div>

        {/* Login Card */}
        <div className="card">
          <h2
            style={{
              fontSize: "1.125rem",
              fontWeight: 600,
              marginBottom: "0.25rem",
            }}
          >
            Secure Access
          </h2>
          <p
            style={{
              fontSize: "0.8125rem",
              color: "var(--muted)",
              marginBottom: "1.5rem",
            }}
          >
            Authorised personnel only. All access is logged and monitored.
          </p>

          {error && (
            <div className="alert alert-error" style={{ marginBottom: "1rem" }}>
              <AlertTriangle size={15} style={{ flexShrink: 0 }} />
              {error}
            </div>
          )}

          <div className="form-group">
            <label className="label">Badge Number or Email Address</label>
            <input
              className="input"
              placeholder="e.g. DCI-4421 or admin@hexshield.go.ke"
              value={loginIdentifier}
              onChange={(e) => setLoginIdentifier(e.target.value)}
              onKeyDown={handleKeyDown}
              autoComplete="username"
            />
          </div>

          <div className="form-group">
            <label className="label">Password</label>
            <div style={{ position: "relative" }}>
              <input
                className="input"
                type={showPassword ? "text" : "password"}
                placeholder="Enter your password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyDown={handleKeyDown}
                autoComplete="current-password"
                style={{ paddingRight: "2.75rem" }}
              />
              <button
                onClick={() => setShowPassword(!showPassword)}
                style={{
                  position: "absolute",
                  right: "0.75rem",
                  top: "50%",
                  transform: "translateY(-50%)",
                  background: "none",
                  border: "none",
                  cursor: "pointer",
                  color: "var(--muted)",
                  padding: 0,
                }}
              >
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          <button
            className="btn btn-primary"
            onClick={handleLogin}
            disabled={loading}
            style={{ width: "100%", marginTop: "0.5rem", padding: "0.75rem" }}
          >
            {loading ? (
              <>
                <div className="loading-spinner" />
                Authenticating...
              </>
            ) : (
              <>
                <Lock size={16} />
                Sign In
              </>
            )}
          </button>
        </div>

        {/* Security Notice */}
        <div
          style={{
            marginTop: "1.5rem",
            padding: "1rem",
            background: "rgba(239,68,68,0.05)",
            border: "1px solid rgba(239,68,68,0.15)",
            borderRadius: 8,
            fontSize: "0.75rem",
            color: "var(--muted)",
            lineHeight: 1.6,
          }}
        >
          <strong style={{ color: "#fca5a5" }}>Security Notice:</strong> This
          system is restricted to authorised DCI personnel only. Unauthorised
          access attempts are logged, traced, and prosecutable under the
          Computer Misuse and Cybercrimes Act, 2018 (Kenya). All sessions are
          monitored and recorded.
        </div>

        <p
          style={{
            textAlign: "center",
            fontSize: "0.75rem",
            color: "var(--muted)",
            marginTop: "1rem",
          }}
        >
          Account access is granted by the ICT Department only.
          <br />
          Contact your system administrator for assistance.
        </p>
      </div>
    </div>
  );
}