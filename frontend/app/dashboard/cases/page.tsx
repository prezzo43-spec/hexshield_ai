// =============================================================================
// HexShield AI — Cases Page
// =============================================================================

"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  FolderOpen,
  Plus,
  Search,
  Filter,
  Calendar,
  User,
} from "lucide-react";
import { listCases, listInvestigators, createCase } from "@/services/api";
import { CASE_STATUS_BG, formatDate } from "@/types";

export default function CasesPage() {
  const [cases, setCases] = useState<any[]>([]);
  const [investigators, setInvestigators] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const [form, setForm] = useState({
    case_reference: "",
    case_title: "",
    description: "",
    lead_investigator_id: "",
    jurisdiction: "Republic of Kenya",
    applicable_law: "Computer Misuse and Cybercrimes Act, 2018",
    classification: "CONFIDENTIAL",
    incident_location: "",
    incident_date: "",
  });

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [casesData, investData] = await Promise.all([
        listCases(),
        listInvestigators(),
      ]);
      setCases(casesData.cases || []);
      setInvestigators(investData.investigators || []);
    } catch (e) {
      setError("Failed to load data.");
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async () => {
    setError("");
    setSuccess("");

    if (!form.case_reference || !form.case_title || !form.lead_investigator_id) {
      setError("Case reference, title, and lead investigator are required.");
      return;
    }

    setSubmitting(true);
    try {
      await createCase(form);
      setSuccess(`Case ${form.case_reference} created successfully.`);
      setShowForm(false);
      setForm({
        case_reference: "",
        case_title: "",
        description: "",
        lead_investigator_id: "",
        jurisdiction: "Republic of Kenya",
        applicable_law: "Computer Misuse and Cybercrimes Act, 2018",
        classification: "CONFIDENTIAL",
        incident_location: "",
        incident_date: "",
      });
      fetchData();
    } catch (e: any) {
      setError(
        e?.response?.data?.detail || "Failed to create case."
      );
    } finally {
      setSubmitting(false);
    }
  };

  const filtered = cases.filter((c) => {
    const matchSearch =
      !search ||
      c.case_reference.toLowerCase().includes(search.toLowerCase()) ||
      c.case_title.toLowerCase().includes(search.toLowerCase());
    const matchStatus = !statusFilter || c.status === statusFilter;
    return matchSearch && matchStatus;
  });

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Forensic Cases</h1>
          <p className="page-subtitle">
            Manage and track all active investigations
          </p>
        </div>
        <button
          className="btn btn-primary"
          onClick={() => setShowForm(!showForm)}
        >
          <Plus size={16} />
          Open New Case
        </button>
      </div>

      {error && (
        <div className="alert alert-error" style={{ marginBottom: "1rem" }}>
          {error}
        </div>
      )}
      {success && (
        <div className="alert alert-success" style={{ marginBottom: "1rem" }}>
          {success}
        </div>
      )}

      {/* New Case Form */}
      {showForm && (
        <div className="card" style={{ marginBottom: "1.5rem" }}>
          <h2 className="section-title">Open New Case</h2>
          <div className="form-row">
            <div className="form-group">
              <label className="label">Case Reference *</label>
              <input
                className="input"
                placeholder="e.g. DCI-2026-00002"
                value={form.case_reference}
                onChange={(e) =>
                  setForm({ ...form, case_reference: e.target.value })
                }
              />
            </div>
            <div className="form-group">
              <label className="label">Classification</label>
              <select
                className="input"
                value={form.classification}
                onChange={(e) =>
                  setForm({ ...form, classification: e.target.value })
                }
              >
                <option>UNCLASSIFIED</option>
                <option>CONFIDENTIAL</option>
                <option>RESTRICTED</option>
                <option>TOP_SECRET</option>
              </select>
            </div>
          </div>

          <div className="form-group">
            <label className="label">Case Title *</label>
            <input
              className="input"
              placeholder="Brief descriptive title for the investigation"
              value={form.case_title}
              onChange={(e) =>
                setForm({ ...form, case_title: e.target.value })
              }
            />
          </div>

          <div className="form-group">
            <label className="label">Description</label>
            <textarea
              className="input"
              rows={3}
              placeholder="Detailed description of the investigation"
              value={form.description}
              onChange={(e) =>
                setForm({ ...form, description: e.target.value })
              }
              style={{ resize: "vertical" }}
            />
          </div>

          <div className="form-row">
            <div className="form-group">
              <label className="label">Lead Investigator *</label>
              <select
                className="input"
                value={form.lead_investigator_id}
                onChange={(e) =>
                  setForm({ ...form, lead_investigator_id: e.target.value })
                }
              >
                <option value="">Select investigator...</option>
                {investigators.map((inv) => (
                  <option key={inv.id} value={inv.id}>
                    {inv.full_name} — {inv.organization}
                  </option>
                ))}
              </select>
            </div>
            <div className="form-group">
              <label className="label">Incident Date</label>
              <input
                className="input"
                type="date"
                value={form.incident_date}
                onChange={(e) =>
                  setForm({ ...form, incident_date: e.target.value })
                }
              />
            </div>
          </div>

          <div className="form-row">
            <div className="form-group">
              <label className="label">Applicable Law</label>
              <input
                className="input"
                value={form.applicable_law}
                onChange={(e) =>
                  setForm({ ...form, applicable_law: e.target.value })
                }
              />
            </div>
            <div className="form-group">
              <label className="label">Incident Location</label>
              <input
                className="input"
                placeholder="e.g. Nairobi CBD"
                value={form.incident_location}
                onChange={(e) =>
                  setForm({ ...form, incident_location: e.target.value })
                }
              />
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
                  Creating...
                </>
              ) : (
                "Create Case"
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

      {/* Filters */}
      <div
        style={{
          display: "flex",
          gap: "0.75rem",
          marginBottom: "1.5rem",
          alignItems: "center",
        }}
      >
        <div style={{ position: "relative", flex: 1, maxWidth: 360 }}>
          <Search
            size={16}
            style={{
              position: "absolute",
              left: 12,
              top: "50%",
              transform: "translateY(-50%)",
              color: "var(--muted)",
            }}
          />
          <input
            className="input"
            style={{ paddingLeft: 36 }}
            placeholder="Search cases..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <select
          className="input"
          style={{ width: 180 }}
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
        >
          <option value="">All Statuses</option>
          <option value="OPEN">Open</option>
          <option value="UNDER_ANALYSIS">Under Analysis</option>
          <option value="PENDING_REVIEW">Pending Review</option>
          <option value="CLOSED">Closed</option>
          <option value="ARCHIVED">Archived</option>
        </select>
      </div>

      {/* Cases Table */}
      <div className="card">
        {loading ? (
          <div className="empty-state">
            <div className="loading-spinner" />
            Loading cases...
          </div>
        ) : filtered.length === 0 ? (
          <div className="empty-state">
            <FolderOpen size={40} className="empty-state-icon" />
            <div>No cases found</div>
            <button
              className="btn btn-primary"
              onClick={() => setShowForm(true)}
            >
              Open First Case
            </button>
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Case Reference</th>
                  <th>Title</th>
                  <th>Status</th>
                  <th>Classification</th>
                  <th>Lead Investigator</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((c) => (
                  <tr key={c.id}>
                    <td>
                      <span
                        style={{
                          fontFamily: "monospace",
                          color: "var(--primary)",
                          fontWeight: 500,
                        }}
                      >
                        {c.case_reference}
                      </span>
                    </td>
                    <td style={{ maxWidth: 280 }}>
                      <div
                        style={{
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {c.case_title}
                      </div>
                    </td>
                    <td>
                      <span
                        className={`badge ${
                          CASE_STATUS_BG[
                            c.status as keyof typeof CASE_STATUS_BG
                          ] || ""
                        }`}
                      >
                        {c.status}
                      </span>
                    </td>
                    <td style={{ color: "var(--muted)", fontSize: "0.8125rem" }}>
                      {c.classification}
                    </td>
                    <td>
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: "0.5rem",
                        }}
                      >
                        <User size={14} color="var(--muted)" />
                        {c.lead_investigator_name}
                      </div>
                    </td>
                    <td style={{ color: "var(--muted)", fontSize: "0.8125rem" }}>
                      {formatDate(c.created_at)}
                    </td>
                    <td>
                      <Link
                        href={`/dashboard/cases/${c.id}`}
                        className="btn btn-outline"
                        style={{ padding: "0.25rem 0.75rem", fontSize: "0.8125rem" }}
                      >
                        View
                      </Link>
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