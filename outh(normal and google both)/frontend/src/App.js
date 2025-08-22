import React, { useState, useEffect } from "react";

function App() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [user, setUser] = useState(null);

  // 🔹 Local Login
  const handleLogin = async () => {
    const res = await fetch("http://localhost:5000/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
      credentials: "include" // for refreshToken cookie
    });
    const data = await res.json();
    if (data.accessToken) {
      localStorage.setItem("accessToken", data.accessToken);
      setUser(data.user);
    }
  };

  // 🔹 Google Login (redirect flow)
  const handleGoogleLogin = () => {
    window.location.href = "http://localhost:5000/auth/google"; 
  };

  // 🔹 Fetch Protected Resource
  const fetchProfile = async () => {
    const accessToken = localStorage.getItem("accessToken");
    const res = await fetch("http://localhost:5000/users/profile", {
      headers: { Authorization: `Bearer ${accessToken}` },
      credentials: "include"
    });

    if (res.status === 401) {
      // Token expired, try refresh
      const refreshRes = await fetch("http://localhost:5000/auth/refresh", {
        method: "POST",
        credentials: "include"
      });
      const refreshData = await refreshRes.json();
      if (refreshData.accessToken) {
        localStorage.setItem("accessToken", refreshData.accessToken);
        return fetchProfile();
      }
    } else {
      const data = await res.json();
      setUser(data);
    }
  };

  // 🔹 Logout
  const handleLogout = async () => {
    await fetch("http://localhost:5000/auth/logout", {
      method: "POST",
      credentials: "include"
    });
    localStorage.removeItem("accessToken");
    setUser(null);
  };

  useEffect(() => {
    fetchProfile();
  }, []);

  return (
    <div style={{ padding: "30px" }}>
      <h2>Auth Demo (Local + Google)</h2>

      {!user ? (
        <>
          <div>
            <h3>Local Login</h3>
            <input
              type="email"
              placeholder="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
            <input
              type="password"
              placeholder="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <button onClick={handleLogin}>Login</button>
          </div>

          <div style={{ marginTop: "20px" }}>
            <h3>Or Login with Google</h3>
            <button onClick={handleGoogleLogin}>Login with Google</button>
          </div>
        </>
      ) : (
        <>
          <h3>Welcome, {user.name}</h3>
          <p>Email: {user.email}</p>
          <button onClick={handleLogout}>Logout</button>
        </>
      )}
    </div>
  );
}

export default App;
