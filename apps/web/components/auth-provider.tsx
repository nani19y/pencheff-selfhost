"use client";

import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { getKeycloak, oidcConfigured } from "@/lib/auth-client";

type AuthContextValue = {
  loading: boolean;
  authenticated: boolean;
  login: () => Promise<void>;
  logout: () => Promise<void>;
  tokenClaims: Record<string, unknown> | null;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [loading, setLoading] = useState(oidcConfigured());
  const [authenticated, setAuthenticated] = useState(!oidcConfigured());
  const [tokenClaims, setTokenClaims] = useState<Record<string, unknown> | null>(null);

  useEffect(() => {
    const kc = getKeycloak();
    if (!kc) {
      setLoading(false);
      return;
    }

    let mounted = true;
    kc.onAuthSuccess = () => mounted && setAuthenticated(true);
    kc.onAuthLogout = () => mounted && setAuthenticated(false);
    kc.onTokenExpired = async () => {
      try {
        await kc.updateToken(30);
        if (mounted) setAuthenticated(true);
      } catch {
        kc.clearToken();
        if (mounted) setAuthenticated(false);
      }
    };

    // Return the authorization response directly to the client-rendered
    // dashboard. The root page performs a server redirect to /dashboard,
    // which would otherwise consume/drop the authorization-code query before
    // keycloak-js can exchange it for tokens.
    const redirectUri = window.location.origin + "/dashboard";

    kc.init({
      onLoad: "login-required",
      redirectUri,
      pkceMethod: "S256",
      checkLoginIframe: false,
    }).then((ok) => {
      if (!mounted) return;
      setAuthenticated(ok);
      setTokenClaims((kc.tokenParsed as Record<string, unknown> | undefined) ?? null);
      setLoading(false);
    }).catch((error) => {
      // Keep the UI in an explicit signed-out state, but do not hide the
      // underlying initialization failure from developers.
      console.error("Keycloak initialization failed:", error);
      if (mounted) {
        setAuthenticated(false);
        setLoading(false);
      }
    });

    return () => {
      mounted = false;
    };
  }, []);

  const value = useMemo<AuthContextValue>(() => ({
    loading,
    authenticated,
    tokenClaims,
    login: async () => {
      await getKeycloak()?.login({
        redirectUri: window.location.origin + "/dashboard",
      });
    },
    logout: async () => {
      await getKeycloak()?.logout({ redirectUri: window.location.origin });
    },
  }), [loading, authenticated, tokenClaims]);

  if (loading) {
    return <div className="min-h-screen grid place-items-center">Authenticating…</div>;
  }

  if (oidcConfigured() && !authenticated) {
    return (
      <div className="min-h-screen grid place-items-center">
        <button onClick={value.login} className="rounded px-4 py-2 border">
          Sign in
        </button>
      </div>
    );
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside <AuthProvider>");
  return value;
}
