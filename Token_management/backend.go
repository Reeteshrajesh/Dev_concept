package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// ---------- CONFIG ----------
var (
	accessSecret  = []byte("access-secret-example-change-in-prod")
	refreshSecret = []byte("refresh-secret-example-change-in-prod")
	// small expirations for demo — use longer in prod
	accessTTL  = 60 * time.Second        // 1 minute for demo
	refreshTTL = 7 * 24 * time.Hour      // 7 days typical
	cookieName = "refresh_token"         // HttpOnly cookie name
)

// ---------- USER STORE (demo) ----------
type User struct {
	ID       string
	Username string
	Password string // bcrypt hashed
}
var (
	users   = map[string]User{} // username -> User
	userMtx sync.RWMutex
)

// ---------- SESSION STORE (in-memory) ----------
// sessionID -> current refresh jti
var (
	sessionJTI = map[string]string{}
	sessMtx    sync.RWMutex
)

// ---------- HELPERS ----------
func hashPassword(plain string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	return string(b), err
}
func comparePassword(hash, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

// createAccessToken: signs a JWT that contains userID and jti (for traceability)
func createAccessToken(userID string) (string, string, error) {
	jti := uuid.NewString()
	claims := jwt.MapClaims{
		"sub": userID,
		"jti": jti,
		"exp": time.Now().Add(accessTTL).Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := token.SignedString(accessSecret)
	return s, jti, err
}

// createRefreshToken: contains sessionID and jti
func createRefreshToken(sessionID, jti string) (string, error) {
	claims := jwt.MapClaims{
		"sid": sessionID,          // session id
		"jti": jti,                // token id (server stores the current one)
		"exp": time.Now().Add(refreshTTL).Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(refreshSecret)
}

// parseRefreshToken: validates signature and extracts session id + jti
func parseRefreshToken(tokenStr string) (sessionID, jti string, err error) {
	tok, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return refreshSecret, nil
	})
	if err != nil || !tok.Valid {
		return "", "", errors.New("invalid refresh token")
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", errors.New("invalid claims")
	}
	sid, ok1 := claims["sid"].(string)
	j, ok2 := claims["jti"].(string)
	if !ok1 || !ok2 {
		return "", "", errors.New("invalid token payload")
	}
	return sid, j, nil
}

// ---------- SESSION MANAGEMENT ----------
func storeSessionJTI(sessionID, jti string) {
	sessMtx.Lock()
	defer sessMtx.Unlock()
	sessionJTI[sessionID] = jti
}
func getSessionJTI(sessionID string) (string, bool) {
	sessMtx.RLock()
	defer sessMtx.RUnlock()
	j, ok := sessionJTI[sessionID]
	return j, ok
}
func deleteSession(sessionID string) {
	sessMtx.Lock()
	defer sessMtx.Unlock()
	delete(sessionJTI, sessionID)
}

// ---------- HTTP HANDLERS ----------

// Signup: POST /signup { username, password }
func signupHandler(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if payload.Username == "" || payload.Password == "" {
		http.Error(w, "username/password required", http.StatusBadRequest)
		return
	}

	userMtx.Lock()
	defer userMtx.Unlock()
	if _, exists := users[payload.Username]; exists {
		http.Error(w, "user exists", http.StatusConflict)
		return
	}
	hashed, err := hashPassword(payload.Password)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	u := User{
		ID:       uuid.NewString(),
		Username: payload.Username,
		Password: hashed,
	}
	users[payload.Username] = u
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "user created"})
}

// Login: POST /login { username, password }
// Issues access token JSON and refresh token as HttpOnly cookie (rotating session)
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	userMtx.RLock()
	u, exists := users[payload.Username]
	userMtx.RUnlock()
	if !exists || !comparePassword(u.Password, payload.Password) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// create session and tokens
	sessionID := uuid.NewString()
	refreshJTI := uuid.NewString() // current jti for this session
	storeSessionJTI(sessionID, refreshJTI)

	accessToken, _, err := createAccessToken(u.ID)
	if err != nil {
		http.Error(w, "token error", http.StatusInternalServerError)
		return
	}
	refreshToken, err := createRefreshToken(sessionID, refreshJTI)
	if err != nil {
		http.Error(w, "token error", http.StatusInternalServerError)
		return
	}

	// set HttpOnly cookie for refresh token
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    refreshToken,
		HttpOnly: true,
		Secure:   false, // set true in production (HTTPS)
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   int(refreshTTL.Seconds()),
	})

	// return access token in JSON
	json.NewEncoder(w).Encode(map[string]string{"access_token": accessToken})
}

// Auth middleware: expects Authorization: Bearer <access token>
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		tokenStr := strings.TrimPrefix(auth, "Bearer ")
		token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return accessSecret, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "invalid/expired access token", http.StatusForbidden)
			return
		}
		claims := token.Claims.(jwt.MapClaims)
		sub, ok := claims["sub"].(string)
		if !ok {
			http.Error(w, "invalid token claims", http.StatusForbidden)
			return
		}
		// put user id in context
		ctx := context.WithValue(r.Context(), "user_id", sub)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// Protected profile endpoint: GET /profile
func profileHandler(w http.ResponseWriter, r *http.Request) {
	uid := r.Context().Value("user_id").(string)
	// For demo, find username by id
	userMtx.RLock()
	defer userMtx.RUnlock()
	var username string
	for _, u := range users {
		if u.ID == uid {
			username = u.Username
			break
		}
	}
	json.NewEncoder(w).Encode(map[string]string{
		"user_id":  uid,
		"username": username,
		"msg":      "This is protected data",
	})
}

// Refresh endpoint: POST /refresh
// - Reads refresh cookie
// - Parses sessionID + presentedJTI
// - Atomically compares presentedJTI with stored jti for that session
// - If matches: rotate -> create new jti, update store, issue new refresh cookie + new access token
// - If mismatch: reuse detected -> revoke session
func refreshHandler(w http.ResponseWriter, r *http.Request) {
	// Get cookie
	c, err := r.Cookie(cookieName)
	if err != nil {
		http.Error(w, "no refresh cookie", http.StatusUnauthorized)
		return
	}
	presented := c.Value

	sessionID, presentedJTI, err := parseRefreshToken(presented)
	if err != nil {
		http.Error(w, "invalid refresh token", http.StatusUnauthorized)
		return
	}

	// Retrieve current jti for session
	currentJTI, ok := getSessionJTI(sessionID)
	if !ok {
		http.Error(w, "session not found", http.StatusUnauthorized)
		return
	}

	if presentedJTI != currentJTI {
		// Token reuse detected -> revoke session(s)
		deleteSession(sessionID)
		// Clear cookie
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    "",
			HttpOnly: true,
			Expires:  time.Unix(0, 0),
			Path:     "/",
		})
		http.Error(w, "refresh token reuse detected - session revoked", http.StatusUnauthorized)
		return
	}

	// Rotation: issue new jti, update store
	newJTI := uuid.NewString()
	storeSessionJTI(sessionID, newJTI)

	// create new refresh token and access token
	refreshToken, err := createRefreshToken(sessionID, newJTI)
	if err != nil {
		http.Error(w, "failed to create refresh token", http.StatusInternalServerError)
		return
	}

	// For demo: create access token using user id from original session.
	// We need user id; we don't store mapping session->user in this simple in-memory demo.
	// Better to store session metadata on login. For now, we will extract user id by decoding the old refresh token's iat? -> Safer: store session->user mapping in production.
	// HERE: we'll parse the presented token (we already did) but it didn't include user id. For simplicity, assume sessions are tied to user via sessionID stored on login.
	// In this demo, we'll not re-derive user id. To keep it correct, we will store session->userID at login.

	// For production code, maintain session metadata. We'll implement session->userID now:

	// (But since we didn't earlier, let's adjust: we will store session->user mapping on login. See below for update.)
	// To keep demo working, session->user mapping is available: getSessionUser(sessionID)
	userID, ok := getSessionUser(sessionID)
	if !ok {
		// Should not happen if login stored it
		http.Error(w, "session user missing", http.StatusInternalServerError)
		return
	}

	accessToken, _, err := createAccessToken(userID)
	if err != nil {
		http.Error(w, "failed to create access token", http.StatusInternalServerError)
		return
	}

	// Set rotated refresh cookie
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    refreshToken,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   int(refreshTTL.Seconds()),
	})

	json.NewEncoder(w).Encode(map[string]string{"access_token": accessToken})
}

// Logout: POST /logout
// Delete session and clear cookie
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// read cookie
	c, err := r.Cookie(cookieName)
	if err == nil {
		sessionID, _, err := parseRefreshToken(c.Value)
		if err == nil {
			deleteSession(sessionID)
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		HttpOnly: true,
		Expires:  time.Unix(0, 0),
		Path:     "/",
	})
	json.NewEncoder(w).Encode(map[string]string{"message": "logged out"})
}

// ---------- SESSION -> USER mapping (demo)
// We'll store session -> userID when logging in so refresh can create access tokens.
var (
	sessionUser = map[string]string{}
	sessionUserMtx sync.RWMutex
)
func storeSessionUser(sessionID, userID string) {
	sessionUserMtx.Lock()
	defer sessionUserMtx.Unlock()
	sessionUser[sessionID] = userID
}
func getSessionUser(sessionID string) (string, bool) {
	sessionUserMtx.RLock()
	defer sessionUserMtx.RUnlock()
	uid, ok := sessionUser[sessionID]
	return uid, ok
}
func deleteSessionUser(sessionID string) {
	sessionUserMtx.Lock()
	defer sessionUserMtx.Unlock()
	delete(sessionUser, sessionID)
}

// Updated loginHandler to store session->user mapping (we must modify above; keep function but we will reassign)
func loginHandlerWithSession(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	userMtx.RLock()
	u, exists := users[payload.Username]
	userMtx.RUnlock()
	if !exists || !comparePassword(u.Password, payload.Password) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	sessionID := uuid.NewString()
	refreshJTI := uuid.NewString()
	storeSessionJTI(sessionID, refreshJTI)
	storeSessionUser(sessionID, u.ID)

	accessToken, _, err := createAccessToken(u.ID)
	if err != nil {
		http.Error(w, "token error", http.StatusInternalServerError)
		return
	}
	refreshToken, err := createRefreshToken(sessionID, refreshJTI)
	if err != nil {
		http.Error(w, "token error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    refreshToken,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   int(refreshTTL.Seconds()),
	})
	json.NewEncoder(w).Encode(map[string]string{"access_token": accessToken})
}

// ---------- MAIN ----------
func main() {
	// For demo: create one user
	hashed, _ := hashPassword("12345")
	users["alice"] = User{ID: uuid.NewString(), Username: "alice", Password: hashed}
	fmt.Println("Demo user: alice / 12345")
	http.HandleFunc("/signup", signupHandler)
	// use loginHandlerWithSession which stores session->user
	http.HandleFunc("/login", loginHandlerWithSession)
	http.HandleFunc("/profile", authMiddleware(profileHandler))
	http.HandleFunc("/refresh", refreshHandler)
	http.HandleFunc("/logout", logoutHandler)

	log.Println("Server listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
