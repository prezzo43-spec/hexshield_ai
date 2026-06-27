// =============================================================================
// HexShield AI — Investigators Page
// =============================================================================

"use client";

import { useEffect, useState } from "react";
import { Users, Plus, Shield, AlertTriangle, CheckCircle } from "lucide-react";
import { listInvestigators, createInvestigator } from "@/services/api";
import { formatDate } from "@/types";

const ROLES = [
  "SYSTEM_ADMIN",
  "LEAD_INVESTIGATOR",
  "FORENSIC_ANALYST",
  "REVIEWING_OFFICER",
  "PROSECUTOR",
  "RESEARCHER",
  "READ_ONLY",
];

export default function InvestigatorsPage() {
  const [investigators, setInvestigators] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const [form, setForm] = useState({
    full_name: "",
    email: "",
    badge_number: "",
    organization: "",
    department: "",
    role: "FORENSIC_ANALYST",
  });

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    setLoading(true);
    try {
      const data = await listInvestigators();
      setInvestigators(data.investigators || []);
    } catch (e) {
      setError("Failed to load investigators.");
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async () => {
    setError("");
    setSuccess("");

    if (!form.full_name || !form.email || !form.organization) {
      setError("Full name, email, and organization are required.");
      return;
    }

    setSubmitting(true);
    try {
      await createInvestigator(form);
      setSuccess(`Investigator ${form.full_name} registered successfully.`);
      setShowForm(false);
      setForm({
        full_name: "",
        email: "",
        badge_number: "",
        organization: "",
        department: "",
        role: "FORENSIC_ANALYST",
      });
      fetchData();
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Failed to register investigator.");
    } finally {
      setSubmitting(false);
    }
  };

  const getRoleColor = (role: string) => {
    const colors: Record<string, string> = {
      SYSTEM_ADMIN: "bg-red-100 text-red-800",
      LEAD_INVESTIGATOR: "bg-blue-100 text-blue-800",
      FORENSIC_ANALYST: "bg-purple-100 text-purple-800",
      REVIEWING_OFFICER: "bg-yellow-100 text-yellow-800",
      PROSECUTOR: "bg-orange-100 text-orange-800",
      RESEARCHER: "bg-green-100 text-green-800",
      READ_ONLY: "bg-gray-100 text-gray-500",
    };
    return colors[role] || "bg-gray-100 text-gray-800";
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Investigators</h1>
          <p className="page-subtitle">
            Manage forensic analysts and law enforcement personnel
          </p>
        </div>
        <button
          className="btn btn-primary"
          onClick={() => setShowForm(!showForm)}
        >
          <Plus size={16} />
          Register Investigator
        </button>
      </div>

      {error && (
        <div className="alert alert-error" style={{ marginBottom: "1rem" }}>
          <AlertTriangle size={16} style={{ flexShrink: 0 }} />
          {error}
        </div>
      )}
      {success && (
        <div className="alert alert-success" style={{ marginBottom: "1rem" }}>
          <CheckCircle size={16} style={{ flexShrink: 0 }} />
          {success}
        </div>
      )}

      {/* Registration Form */}
      {showForm && (
        <div className="card" style={{ marginBottom: "1.5rem" }}>
          <h2 className="section-title">Register New Investigator</h2>

          <div className="form-row">
            <div className="form-group">
              <label className="label">Full Name *</label>
              <input
                className="input"
                placeholder="e.g. Dr. John Kamau"
                value={form.full_name}
                onChange={(e) =>
                  setForm({ ...form, full_name: e.target.value })
                }
              />
            </div>
            <div className="form-group">
              <label className="label">Email Address *</label>
              <input
                className="input"
                type="email"
                placeholder="investigator@dci.go.ke"
                value={form.email}
                onChange={(e) =>
                  setForm({ ...form, email: e.target.value })
                }
              />
            </div>
          </div>

          <div className="form-row">
            <div className="form-group">
              <label className="label">Organization *</label>
              <input
                className="input"
                placeholder="e.g. Directorate of Criminal Investigations"
                value={form.organization}
                onChange={(e) =>
                  setForm({ ...form, organization: e.target.value })
                }
              />
            </div>
            <div className="form-group">
              <label className="label">Department</label>
              <input
                className="input"
                placeholder="e.g. Digital Forensics Unit"
                value={form.department}
                onChange={(e) =>
                  setForm({ ...form, department: e.target.value })
                }
              />
            </div>
          </div>

          <div className="form-row">
            <div className="form-group">
              <label className="label">Badge Number</label>
              <input
                className="input"
                placeholder="e.g. DCI-4421"
                value={form.badge_number}
                onChange={(e) =>
                  setForm({ ...form, badge_number: e.target.value })
                }
              />
            </div>
            <div className="form-group">
              <label className="label">Role</label>
              <select
                className="input"
                value={form.role}
                onChange={(e) =>
                  setForm({ ...form, role: e.target.value })
                }
              >
                {ROLES.map((r) => (
                  <option key={r} value={r}>
                    {r.replace(/_/g, " ")}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div style={{ display: "flex", gap: "0.75rem" }}>
            <button
              className="btn btn-primary"
              onClick={handleSubmit}
              disabled={submitting}
            >
              {submitting ? (
                <>
                  <div className="loading-spinner" />
                  Registering...
                </>
              ) : (
                "Register"
              )}
            </button>
            <button
              className="btn btn-outline"
              onClick={() => setShowForm(false)}
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Investigators Table */}
      <div className="card">
        {loading ? (
          <div className="empty-state">
            <div className="loading-spinner" />
            Loading investigators...
          </div>
        ) : investigators.length === 0 ? (
          <div className="empty-state">
            <Users size={40} className="empty-state-icon" />
            <div>No investigators registered</div>
            <button
              className="btn btn-primary"
              onClick={() => setShowForm(true)}
            >
              Register First Investigator
            </button>
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Email</th>
                  <th>Badge</th>
                  <th>Organization</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th>Registered</th>
                </tr>
              </thead>
              <tbody>
                {investigators.map((inv) => (
                  <tr key={inv.id}>
                    <td>
                      <div style={{ fontWeight: 500 }}>{inv.full_name}</div>
                      {inv.department && (
                        <div
                          style={{
                            fontSize: "0.75rem",
                            color: "var(--muted)",
                          }}
                        >
                          {inv.department}
                        </div>
                      )}
                    </td>
                    <td style={{ color: "var(--muted)", fontSize: "0.875rem" }}>
                      {inv.email}
                    </td>
                    <td>
                      {inv.badge_number ? (
                        <span
                          style={{
                            fontFamily: "monospace",
                            fontSize: "0.8125rem",
                          }}
                        >
                          {inv.badge_number}
                        </span>
                      ) : (
                        <span style={{ color: "var(--muted)" }}>—</span>
                      )}
                    </td>
                    <td style={{ fontSize: "0.875rem" }}>
                      {inv.organization}
                    </td>
                    <td>
                      <span className={`badge ${getRoleColor(inv.role)}`}>
                        {inv.role.replace(/_/g, " ")}
                      </span>
                    </td>
                    <td>
                      <span
                        className={`badge ${
                          inv.is_active
                            ? "bg-green-100 text-green-800"
                            : "bg-gray-100 text-gray-500"
                        }`}
                      >
                        {inv.is_active ? "Active" : "Inactive"}
                      </span>
                    </td>
                    <td
                      style={{
                        color: "var(--muted)",
                        fontSize: "0.8125rem",
                      }}
                    >
                      {formatDate(inv.created_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}