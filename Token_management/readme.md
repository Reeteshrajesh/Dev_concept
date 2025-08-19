# 🔐 Go + React JWT Auth (Access & Refresh Token Demo)

This project demonstrates a **secure authentication system** with **JWT access & refresh tokens**, implemented in:

* **Backend** → Go (`net/http`)
* **Frontend** → React (single `App.js`)

It shows **modern best practices**: short-lived access tokens, HttpOnly refresh tokens with rotation, session revocation on reuse, and proper frontend token handling.

---

## 🚀 Features

* ✅ Signup & login with bcrypt password hashing
* ✅ JWT **Access Tokens** (short-lived, \~1 minute for demo)
* ✅ JWT **Refresh Tokens** with **rotation (single-use)**
* ✅ In-memory session store (map + mutex) for demo
* ✅ Refresh token reuse detection & session revocation
* ✅ Refresh token delivered as **HttpOnly Secure cookie**
* ✅ Endpoints: `/signup`, `/login`, `/profile` (protected), `/refresh`, `/logout`
* ✅ React frontend: access token in **memory**, refresh token in **cookie**
* ✅ Auto-refresh on token expiry

---

## 🧠 Security Model

### 🔑 Tokens

* **Access Token**

  * JWT
  * Short-lived (\~60s in demo, 10–15min in prod)
  * Sent in `Authorization: Bearer <token>`

* **Refresh Token**

  * JWT containing `session_id` and `jti`
  * Sent as **HttpOnly cookie** (safe from JavaScript/XSS)
  * Single-use (rotated each refresh)

---

### 🔄 Refresh Rotation Strategy

1. On login, backend issues **access token + refresh token**.
2. Server stores the current `jti` (unique ID) per `session_id`.
3. On `/refresh`:

   * Check refresh token is valid and its `jti` matches stored one.
   * If valid → issue new access + refresh tokens and update stored `jti`.
   * If mismatch → **reuse detected → revoke session**.

👉 This prevents replay: stolen refresh tokens can’t be reused.

---

### 📦 Storage

* **Access Token** → In **React state** (memory)
* **Refresh Token** → In **HttpOnly cookie** (browser sends automatically)
* **Why?**

  * Access token in memory avoids persistent theft.
  * Refresh token in HttpOnly cookie prevents XSS exfiltration.

---

## 📂 Project Structure

```
Token-management/
│── backend.go
│── frontend.js
│── README.md
```

---

## 🔧 Backend (Go)

* **Secrets:**

  * `accessSecret` → signs access tokens
  * `refreshSecret` → signs refresh tokens
  * (In production, load from `.env` with a secret manager)

* **Session Store:**

  * In-memory `map[sessionID]jti` for demo
  * Replace with **Redis/DB** in production

* **Cookie Security:**

  * `HttpOnly: true` (JS can’t access)
  * `Secure: true` (only HTTPS)
  * `SameSite: Strict` (protect CSRF)

---

## 🎨 Frontend (React)

* Stores access token in memory (`useState`)
* Sends refresh token automatically (HttpOnly cookie) via `fetch(..., { credentials: "include" })`
* On **401/403** response:

  1. Calls `/refresh` to get new access token
  2. Retries the original request
  3. If refresh also fails → logout

---

## ▶️ How to Run Locally

### 1️⃣ Backend

```bash
cd backend
go mod init go-jwt-refresh-demo
go get github.com/golang-jwt/jwt/v5
go run main.go
```

Server runs on `http://localhost:8080`

---

### 2️⃣ Frontend

```bash
npx create-react-app token-demo
cd token-demo
# replace src/App.js with provided App.js
npm start
```

Frontend runs on `http://localhost:3000`

---

## 🧪 Test Flow

1. Signup → `POST /signup`
2. Login → sets HttpOnly refresh cookie + returns access token
3. Call `/profile` with `Authorization: Bearer <access_token>`
4. Wait 60s → access token expires
5. Retry `/profile` → React auto-calls `/refresh`, retries request
6. Logout → `POST /logout` clears session

---

## 🔒 Production Notes

* Use **Postgres/Redis** for refresh sessions
* Use **TLS/HTTPS** for all traffic
* Rotate signing keys securely
* Consider refresh **token blacklist** on logout
* Use CSRF protection if refresh cookies are cross-site

---

## ✅ Summary

This project demonstrates:

* **Secure login with Go backend**
* **Access + refresh token strategy with rotation**
* **Safe frontend token storage in React**
* **Practical flow for real-world apps**

It’s a **foundation for production-ready authentication**.
