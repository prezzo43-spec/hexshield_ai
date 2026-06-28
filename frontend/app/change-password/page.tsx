// =============================================================================
// HexShield AI — Change Password Page
// Shown on first login — forces password change before accessing the system.
// =============================================================================

"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Shield, AlertTriangle, CheckCircle, Eye, EyeOff } from "lucide-react";
import { api } from "@/services/api";
import { useAuth } from "@/contexts/AuthContext";

export default function ChangePasswordPage() {
  const router = useRouter();
  const { investigator } = useAuth();

  const [form, setForm] = useState({
    current_password: "",
    new_password: "",
    confirm_password: "",
  });
  const [showPasswords, setShowPasswords] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);

  const requirements = [
    { label: "Minimum 12 characters", met: form.new_password.length >= 12 },
    { label: "At least one uppercase letter", met: /[A-Z]/.test(form.new_password) },
    { label: "At least one lowercase letter", met: /[a-z]/.test(form.new_password) },
    { label: "At least one digit", met: /[0-9]/.test(form.new_password) },
    {
      label: "At least one special character",
      met: /[!@#$%^&*()_+\-=\[\]{}|;':",./<>?]/.test(form.new_password),
    },
    {
      label: "Passwords match",
      met:
        form.new_password.length > 0 &&
        form.new_password === form.confirm_password,
    },
  ];

  const allMet = requirements.every((r) => r.met);

  const handleSubmit = async () => {
    setError("");
    if (!allMet) {
      setError("Please meet all password requirements.");
      return;
    }
    setLoading(true);
    try {
      await api.post("/api/v1/auth/change-password", form);
      setSuccess(true);
      setTimeout(() => router.push("/dashboard"), 2000);
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Failed to change password.");
    } finally {
      setLoading(false);
    }
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
      <div style={{ width: "100%", maxWidth: 480 }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "0.75rem",
            marginBottom: "2rem",
          }}
        >
          <div
            style={{
              width: 48,
              height: 48,
              background: "var(--primary)",
              borderRadius: 12,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <Shield size={24} color="white" />
          </div>
          <div>
            <h1 style={{ fontSize: "1.25rem", fontWeight: 700 }}>
              HexShield AI
            </h1>
            <p style={{ fontSize: "0.8125rem", color: "var(--muted)" }}>
              Password Setup Required
            </p>
          </div>
        </div>

        <div className="card">
          <h2 style={{ fontSize: "1.125rem", fontWeight: 600, marginBottom: "0.5rem" }}>
            Set Your Password
          </h2>
          <p style={{ fontSize: "0.875rem", color: "var(--muted)", marginBottom: "1.5rem" }}>
            Welcome, {investigator?.full_name}. You must set a new password
            before accessing the system.
          </p>

          {error && (
            <div className="alert alert-error" style={{ marginBottom: "1rem" }}>
              <AlertTriangle size={15} style={{ flexShrink: 0 }} />
              {error}
            </div>
          )}

          {success && (
            <div className="alert alert-success" style={{ marginBottom: "1rem" }}>
              <CheckCircle size={15} style={{ flexShrink: 0 }} />
              Password changed successfully. Redirecting to dashboard...
            </div>
          )}

          <div className="form-group">
            <label className="label">Current Password</label>
            <input
              className="input"
              type={showPasswords ? "text" : "password"}
              placeholder="Your temporary password"
              value={form.current_password}
              onChange={(e) =>
                setForm({ ...form, current_password: e.target.value })
              }
            />
          </div>

          <div className="form-group">
            <label className="label">New Password</label>
            <input
              className="input"
              type={showPasswords ? "text" : "password"}
              placeholder="Create a strong password"
              value={form.new_password}
              onChange={(e) =>
                setForm({ ...form, new_password: e.target.value })
              }
            />
          </div>

          <div className="form-group">
            <label className="label">Confirm New Password</label>
            <input
              className="input"
              type={showPasswords ? "text" : "password"}
              placeholder="Repeat your new password"
              value={form.confirm_password}
              onChange={(e) =>
                setForm({ ...form, confirm_password: e.target.value })
              }
            />
          </div>

          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.5rem",
              marginBottom: "1rem",
              cursor: "pointer",
              fontSize: "0.8125rem",
              color: "var(--muted)",
            }}
            onClick={() => setShowPasswords(!showPasswords)}
          >
            {showPasswords ? <EyeOff size={15} /> : <Eye size={15} />}
            {showPasswords ? "Hide" : "Show"} passwords
          </div>

          {/* Password Requirements */}
          <div
            style={{
              background: "var(--background)",
              borderRadius: 8,
              padding: "0.875rem",
              marginBottom: "1rem",
            }}
          >
            <div
              style={{
                fontSize: "0.75rem",
                fontWeight: 600,
                color: "var(--muted)",
                marginBottom: "0.5rem",
              }}
            >
              PASSWORD REQUIREMENTS
            </div>
            {requirements.map((req, i) => (
              <div
                key={i}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "0.5rem",
                  fontSize: "0.8125rem",
                  color: req.met ? "var(--success)" : "var(--muted)",
                  marginBottom: "0.25rem",
                }}
              >
                <CheckCircle size={13} opacity={req.met ? 1 : 0.3} />
                {req.label}
              </div>
            ))}
          </div>

          <button
            className="btn btn-primary"
            onClick={handleSubmit}
            disabled={loading || !allMet || success}
            style={{ width: "100%", padding: "0.75rem" }}
          >
            {loading ? (
              <>
                <div className="loading-spinner" />
                Updating...
              </>
            ) : (
              "Set Password and Continue"
            )}
          </button>
        </div>
      </div>
    </div>
  );
}