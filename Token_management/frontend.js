import React, { useState } from "react";

const API = "http://localhost:8080"; // adjust if needed

function App() {
  const [accessToken, setAccessToken] = useState(null);
  const [profile, setProfile] = useState(null);
  const [username, setUsername] = useState("alice");
  const [password, setPassword] = useState("12345");
  const [status, setStatus] = useState("");

  async function login() {
    setStatus("logging in...");
    const res = await fetch(`${API}/login`, {
      method: "POST",
      credentials: "include", // important: receive HttpOnly cookie
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      setStatus("login failed");
      const t = await res.text();
      console.error(t);
      return;
    }
    const data = await res.json();
    setAccessToken(data.access_token);
    setStatus("logged in (access token in memory). Refresh token is in cookie.");
  }

  async function getProfile() {
    setStatus("fetching profile...");
    // Try protected endpoint with current accessToken
    let res = await fetch(`${API}/profile`, {
      headers: { Authorization: `Bearer ${accessToken}` },
      credentials: "include",
    });

    if (res.status === 401 || res.status === 403) {
      // Access token expired or invalid -> try refresh
      setStatus("access token expired, trying refresh...");
      const refreshRes = await fetch(`${API}/refresh`, {
        method: "POST",
        credentials: "include", // sends HttpOnly refresh cookie
      });
      if (!refreshRes.ok) {
        setStatus("refresh failed - need login");
        setAccessToken(null);
        return;
      }
      const refreshData = await refreshRes.json();
      setAccessToken(refreshData.access_token);

      // retry profile
      res = await fetch(`${API}/profile`, {
        headers: { Authorization: `Bearer ${refreshData.access_token}` },
        credentials: "include",
      });
    }

    if (!res.ok) {
      setStatus("failed to fetch profile");
      const t = await res.text();
      console.error(t);
      return;
    }
    const data = await res.json();
    setProfile(data);
    setStatus("profile fetched");
  }

  async function logout() {
    await fetch(`${API}/logout`, { method: "POST", credentials: "include" });
    setAccessToken(null);
    setProfile(null);
    setStatus("logged out");
  }

  return (
    <div style={{ padding: 20 }}>
      <h2>Access + Refresh Token Demo (React)</h2>

      <div>
        <label>username: </label>
        <input value={username} onChange={(e) => setUsername(e.target.value)} />
        <label> password: </label>
        <input value={password} onChange={(e) => setPassword(e.target.value)} />
        <button onClick={login}>Login</button>
        <button onClick={logout} style={{ marginLeft: 8 }}>
          Logout
        </button>
      </div>

      <div style={{ marginTop: 12 }}>
        <button onClick={getProfile}>Get Profile (protected)</button>
      </div>

      <div style={{ marginTop: 12 }}>
        <b>Status:</b> {status}
      </div>

      <div style={{ marginTop: 12 }}>
        <b>Access token (in memory):</b>
        <pre style={{ maxWidth: 800, whiteSpace: "pre-wrap" }}>{accessToken}</pre>
      </div>

      <div style={{ marginTop: 12 }}>
        <b>Profile:</b>
        <pre>{profile ? JSON.stringify(profile, null, 2) : "no profile yet"}</pre>
      </div>

      <div style={{ marginTop: 24, color: "#666" }}>
        <small>
          Refresh token stored in <code>HttpOnly</code> cookie (browser). Access token stored only in
          memory (this React state). Refresh flow uses <code>/refresh</code> endpoint and rotates
          refresh token on each use.
        </small>
      </div>
    </div>
  );
}

export default App;
