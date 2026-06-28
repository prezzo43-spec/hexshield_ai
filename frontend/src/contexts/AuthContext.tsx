// =============================================================================
// HexShield AI — Authentication Context
// Manages global auth state across the entire frontend application.
// =============================================================================

"use client";

import {
  createContext,
  useContext,
  useEffect,
  useState,
  useCallback,
  ReactNode,
} from "react";
import { api } from "@/services/api";

interface Investigator {
  id: string;
  full_name: string;
  email: string;
  badge_number: string | null;
  role: string;
  organization: string;
  first_login: boolean;
}

interface AuthContextType {
  investigator: Investigator | null;
  loading: boolean;
  login: (login_identifier: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [investigator, setInvestigator] = useState<Investigator | null>(null);
  const [loading, setLoading] = useState(true);

  // Check if user is already logged in on page load
  const checkAuth = useCallback(async () => {
    try {
      const res = await api.get("/api/v1/auth/me");
      setInvestigator(res.data);
    } catch {
      setInvestigator(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  const login = async (login_identifier: string, password: string) => {
    const res = await api.post("/api/v1/auth/login", {
      login_identifier,
      password,
    });
    setInvestigator(res.data.investigator);
  };

  const logout = async () => {
    try {
      await api.post("/api/v1/auth/logout");
    } finally {
      setInvestigator(null);
      window.location.href = "/login";
    }
  };

  return (
    <AuthContext.Provider
      value={{
        investigator,
        loading,
        login,
        logout,
        isAuthenticated: !!investigator,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}