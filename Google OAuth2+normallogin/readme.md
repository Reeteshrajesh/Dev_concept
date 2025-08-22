# 🔐 Fullstack Auth Example (Local + Google OAuth)

This project demonstrates a **complete authentication workflow** with:

* ✅ Local (email + password) login & signup
* ✅ Google OAuth2 login
* ✅ JWT-based authentication
* ✅ Refresh tokens for session management
* ✅ Frontend (React) + Backend (Node.js/Express)

---

## 📂 Project Structure

```
auth-project/
├── backend/
│   └── server.js     # Node.js + Express backend
└── frontend/
    └── src.js        # React frontend with login (local + Google)
```

---

## ⚙️ Backend (server.js)

* **Local Auth**:

  * `POST /api/signup` → Creates a new user (stores hashed password).
  * `POST /api/login` → Validates email/password, issues JWT + refresh token.

* **Google Auth**:

  * `GET /api/auth/google` → Redirects to Google OAuth.
  * `GET /api/auth/google/callback` → Handles Google response, issues JWT + refresh token.

* **Token Management**:

  * Access Token (short-lived, e.g. 15m).
  * Refresh Token (long-lived, stored securely in DB or memory).
  * `POST /api/refresh` → Exchanges refresh token for new access token.

---

## 🎨 Frontend (src.js)

* **Login Options**:

  * **Email/Password** form → Calls `/api/login`.
  * **Google Login Button** → Redirects to `/api/auth/google`.

* **Token Handling**:

  * Access token stored in memory (or `localStorage`).
  * Refresh token handled by backend.
  * Automatically refreshes token before expiry by calling `/api/refresh`.

---

## 🔄 Workflow

### 1. Local Login

1. User enters email + password in React.
2. React calls `POST /api/login`.
3. Backend verifies credentials.
4. Backend returns:

   * `accessToken` (JWT, short-lived)
   * `refreshToken` (long-lived)
5. Frontend stores `accessToken` and uses it in headers for API requests.

---

### 2. Google Login

1. User clicks **"Login with Google"** button.
2. React redirects to `/api/auth/google`.
3. User completes Google OAuth screen.
4. Backend handles callback, creates user if new.
5. Backend issues JWT + refresh token.
6. React receives tokens and stores them.

---

### 3. Token Refresh

1. When access token expires, frontend calls `POST /api/refresh` with `refreshToken`.
2. Backend validates refresh token.
3. Backend issues a new `accessToken`.
4. Frontend updates stored token and continues.

---

## 🚀 How to Run

### 1. Backend

```bash
cd backend
npm install express cors body-parser jsonwebtoken bcryptjs passport passport-google-oauth20
node server.js
```

Set your Google OAuth credentials in `.env`:

```env
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
JWT_SECRET=your-secret
```

### 2. Frontend

```bash
cd frontend
npm install react react-dom axios
npm start
```

---

## 🛠️ Example Protected API Call

```javascript
axios.get("http://localhost:4000/api/protected", {
  headers: { Authorization: `Bearer ${accessToken}` }
});
```

If expired → frontend automatically uses refresh token to get a new access token.

---

## ✅ Key Points

* **Access tokens** should **never be stored in cookies** (XSS risk). Store in memory/localStorage.
* **Refresh tokens** should be stored **securely** (ideally HttpOnly cookie or backend DB).
* Always validate JWTs on backend for protected routes.

---

👉 With this setup, you have a **production-style authentication workflow** with both **local login** and **Google OAuth**.

---
