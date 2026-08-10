"use client";

import { createContext, useContext } from "react";

/**
 * Auth-check result, computed once by `app/(shell)/layout.tsx` and shared
 * by every page it wraps. Replaces the identical authed/authChecked
 * useState+useEffect pair that used to be duplicated in each of those
 * pages — since none of them shared a persistent layout, every single
 * navigation between them unmounted and remounted the pair, forcing a
 * fresh post-mount effect (and a blank first frame) on every nav instead
 * of just once per app session.
 */
export interface ShellAuthStatus {
  /** True once the one-time client-side auth check has run. */
  authChecked: boolean;
  /** True if that check found a valid sp_token. */
  authed: boolean;
}

export const ShellAuthContext = createContext<ShellAuthStatus>({
  authChecked: false,
  authed: false,
});

export function useShellAuth(): ShellAuthStatus {
  return useContext(ShellAuthContext);
}
