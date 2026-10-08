"use client";

import Keycloak, { type KeycloakInstance } from "keycloak-js";

let client: KeycloakInstance | null = null;

export function oidcConfigured(): boolean {
  return Boolean(
    process.env.NEXT_PUBLIC_OIDC_URL &&
    process.env.NEXT_PUBLIC_OIDC_REALM &&
    process.env.NEXT_PUBLIC_OIDC_CLIENT_ID,
  );
}

export function getKeycloak(): KeycloakInstance | null {
  if (!oidcConfigured()) return null;
  if (!client) {
    client = new Keycloak({
      url: process.env.NEXT_PUBLIC_OIDC_URL!,
      realm: process.env.NEXT_PUBLIC_OIDC_REALM!,
      clientId: process.env.NEXT_PUBLIC_OIDC_CLIENT_ID!,
    });
  }
  return client;
}

export async function getAccessToken(): Promise<string | null> {
  const kc = getKeycloak();
  if (!kc?.authenticated) return null;
  try {
    await kc.updateToken(30);
    return kc.token ?? null;
  } catch {
    kc.clearToken();
    return null;
  }
}
