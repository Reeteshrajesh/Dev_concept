// src/App.js
import React, { useEffect, useState, useRef } from "react";

/**
 * Configuration
 */
const API = process.env.REACT_APP_API_URL || "http://localhost:5000";
const GOOGLE_LOGIN_URL = `${API}/auth/google`;

/**
 * Simple helper to parse query params (to read accessToken returned via redirect)
 */
function getQueryParams() {
  if (typeof window === "undefined") return {};
  return Object.fromEntries(new URLSearchParams(window.location.search));
}

/**
 * Global refresh promise to avoid multiple concurrent refresh calls.
 * When a refresh is in progress, other requests should wait on this.
 */
let refreshPromise = null;

/**
 * fetchWithAuth
 * - Sends request with Authorization header using current in-memory accessToken
 * - If request returns 401/403, tries to refresh via POST /auth/refresh (sends cookie)
 * - On successful refresh, retries original request once
 * - If refresh fails -> calls onRefreshFail (usually logout)
 */
async function fetchWithAuth(input, init = {}, getAccessToken, setAccessToken, onRefreshFail) {
  const token = getAccessToken();
  const headers = new Headers(init.headers || {});
  if (token) headers.set("Authorization", `Bearer ${token}`);

  const opts = {
    ...init,
    headers,
    credentials: "include", // ensure cookies (refresh) are sent
  };

  let res = await fetch(input, opts);
  if (res.status !== 401 && res.status !== 403) {
    return res;
  }

  // attempt refresh. If another refresh is in flight, wait for it.
  if (!refreshPromise) {
    refreshPromise = (async () => {
      try {
        const r = await fetch(`${API}/auth/refresh`, {
          method: "POST",
          credentials: "include",
        });
        if (!r.ok) throw new Error("refresh failed");
        const j = await r.json();
        if (j.accessToken) {
          setAccessToken(j.accessToken);
          return j.accessToken;
        }
        throw new Error("no access token");
      } catch (err) {
        // refresh failed
        throw err;
      } finally {
        // will be cleared by callers
      }
    })();
  }

  try {
    const newToken = await refreshPromise;
    refreshPromise = null;
    // retry original request with new token
    const headers2 = new Headers(init.headers || {});
    headers2.set("Authorization", `Bearer ${newToken}`);
    const opts2 = {
      ...init,
      headers: headers2,
      credentials: "include",
    };
    return await fetch(input, opts2);
  } catch (err) {
    refreshPromise = null;
    onRefreshFail && onRefreshFail();
    throw err;
  }
}

/**
 * Main App component
 */
export default function App() {
  // Auth state
  const [accessToken, setAccessToken] = useState(null);
  const accessTokenRef = useRef(null); // keep ref to latest token for helpers
  useEffect(() => (accessTokenRef.current = accessToken), [accessToken]);
  const getAccessToken = () => accessTokenRef.current;

  // UI state
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [profile, setProfile] = useState(null);
  const [status, setStatus] = useState("");

  // On mount: if backend redirected back with accessToken in query, use it.
  useEffect(() => {
    const q = getQueryParams();
    if (q.accessToken) {
      setAccessToken(q.accessToken);
      // remove query param from URL for cleanliness
      const url = new URL(window.location.href);
      url.searchParams.delete("accessToken");
      window.history.replaceState({}, document.title, url.pathname + url.search);
      setStatus("Logged in via Google redirect.");
    }
  }, []);

  // Helper: handle refresh failing -> logout locally
  const handleRefreshFailure = () => {
    setAccessToken(null);
    setProfile(null);
    setStatus("Session expired. Please log in again.");
  };

  // Local register
  const register = async () => {
    setStatus("Registering...");
    try {
      const res = await fetch(`${API}/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ email, password, name }),
      });
      const j = await res.json();
      if (!res.ok) {
        setStatus("Register failed: " + (j.error || res.status));
        return;
      }
      setAccessToken(j.accessToken);
      setStatus("Registered & logged in.");
    } catch (err) {
      console.error(err);
      setStatus("Registration error");
    }
  };

  // Local login
  const login = async () => {
    setStatus("Logging in...");
    try {
      const res = await fetch(`${API}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include", // so backend can set refresh cookie
        body: JSON.stringify({ email, password }),
      });
      const j = await res.json();
      if (!res.ok) {
        setStatus("Login failed: " + (j.error || res.status));
        return;
      }
      setAccessToken(j.accessToken);
      setStatus("Logged in");
    } catch (err) {
      console.error(err);
      setStatus("Login error");
    }
  };

  // Google login (redirect to backend)
  const loginWithGoogle = () => {
    // backend /auth/google will redirect to Google consent screen
    window.location.href = GOOGLE_LOGIN_URL;
  };

  // Fetch profile (protected)
  const fetchProfile = async () => {
    setStatus("Fetching profile...");
    try {
      const res = await fetchWithAuth(
        `${API}/users/profile`,
        { method: "GET" },
        getAccessToken,
        setAccessToken,
        handleRefreshFailure
      );
      if (!res.ok) {
        setStatus("Failed to fetch profile: " + res.status);
        return;
      }
      const j = await res.json();
      setProfile(j);
      setStatus("Profile loaded");
    } catch (err) {
      console.error(err);
      setStatus("Error fetching profile");
    }
  };

  // Logout
  const logout = async () => {
    try {
      await fetch(`${API}/auth/logout`, { method: "POST", credentials: "include" });
    } catch (e) {}
    setAccessToken(null);
    setProfile(null);
    setStatus("Logged out");
  };

  return (
    <div style={{ padding: 24, fontFamily: "sans-serif", maxWidth: 800 }}>
      <h1>Auth Demo — Local + Google (Access + Refresh tokens)</h1>

      <div style={{ marginBottom: 12 }}>
        <strong>Status:</strong> {status}
      </div>

      <div style={{ display: "flex", gap: 12 }}>
        <div style={{ flex: 1 }}>
          <h3>Local Register / Login</h3>
          <input
            placeholder="Name (for register)"
            value={name}
            onChange={(e) => setName(e.target.value)}
            style={{ display: "block", marginBottom: 8, width: "100%" }}
          />
          <input
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            style={{ display: "block", marginBottom: 8, width: "100%" }}
          />
          <input
            placeholder="Password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            style={{ display: "block", marginBottom: 8, width: "100%" }}
          />
          <div style={{ display: "flex", gap: 8 }}>
            <button onClick={register}>Register</button>
            <button onClick={login}>Login</button>
            <button onClick={logout}>Logout</button>
          </div>
        </div>

        <div style={{ width: 1, background: "#ddd" }} />

        <div style={{ flex: 1 }}>
          <h3>Google Login</h3>
          <p>
            Click below to login via Google. This redirects to backend <code>/auth/google</code> which
            handles the OAuth flow.
          </p>
          <button onClick={loginWithGoogle}>Login with Google</button>

          <hr />

          <h3>Profile / Protected</h3>
          <button onClick={fetchProfile}>Fetch Profile (protected)</button>
          {profile && (
            <pre style={{ whiteSpace: "pre-wrap", marginTop: 12 }}>{JSON.stringify(profile, null, 2)}</pre>
          )}
        </div>
      </div>

      <div style={{ marginTop: 20 }}>
        <h4>Access Token (in-memory)</h4>
        <textarea
          readOnly
          rows={4}
          value={accessToken || "<no access token>"}
          style={{ width: "100%" }}
        />
        <small style={{ color: "#666" }}>
          Access token is kept in memory for security. Refresh token is stored in an HttpOnly cookie
          (sent automatically by browser).
        </small>
      </div>

      <div style={{ marginTop: 16 }}>
        <strong>Notes:</strong>
        <ul>
          <li>Make sure backend is running at <code>{API}</code>.</li>
          <li>Cookies require the backend to set proper CORS (credentials: true) and cookie options.</li>
          <li>In production use HTTPS and set cookie <code>Secure</code> to true.</li>
          <li>For concurrency safety this client queues refresh requests via a single global promise.</li>
        </ul>
      </div>
    </div>
  );
}
