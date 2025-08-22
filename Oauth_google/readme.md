# Google OAuth Login (Node.js + Express)

This is a simple example of integrating **Google Login** into a custom signup/login system using **Node.js, Express, and JWT**.

---

## Features

* Login with **Google OAuth 2.0**
* Fetch user profile (`email`, `name`, `picture`) from Google
* Link Google user to your app’s database
* Issue your own **JWT session token** stored in an **httpOnly cookie**
* Redirect to `/dashboard` after login

---

## Setup

###  Create Google OAuth App

1. Go to [Google Cloud Console](https://console.cloud.google.com/).
2. Create a project → Enable **OAuth Consent Screen**.
3. Create **OAuth 2.0 Client ID (Web Application)**.

   * Redirect URI:

     ```
     https://yourapp.com/auth/google/callback
     ```
4. Copy **Client ID** and **Client Secret**.

---

###  Environment Variables

Create a `.env` file:

```env
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
JWT_SECRET=supersecretjwtkey
```

---

### Run Server

```bash
node server.js
```

Server will start on:

```
https://yourapp.com
```

---

## Endpoints

* **`GET /auth/google`** → Redirects to Google login.
* **`GET /auth/google/callback`** → Handles Google’s redirect, fetches profile, issues JWT, and sets cookie.

---

## Login Flow

1. User clicks **Continue with Google**.
2. Redirect → Google login → back to `/auth/google/callback`.
3. Exchange `code` → get `access_token` + `id_token`.
4. Fetch profile from Google API.
5. Check/Create user in DB.
6. Issue JWT → store in **httpOnly cookie**.
7. Redirect to `/dashboard`.

---

## Security Notes

* Always keep `GOOGLE_CLIENT_SECRET` and `JWT_SECRET` safe (use AWS Secrets Manager, Vault, etc. in production).
* Use `secure: true` cookies in production (works only on HTTPS).
* Implement **logout** by clearing `auth_token` cookie.
* Expand DB logic (`findUserByEmail`, `createUser`) to use your actual database.

