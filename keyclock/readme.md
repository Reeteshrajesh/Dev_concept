Perfect 👍 thanks for sharing the official **Grafana + Keycloak OAuth2 docs**.
I’ve gone through it carefully, and I’ll explain:

---

## 🔎 What you did wrong so far

1. **Scopes** –
   In your `docker-compose.yml` you only had:

   ```yaml
   GF_AUTH_GENERIC_OAUTH_SCOPES: "openid profile email"
   ```

   But the docs require:

   ```
   openid email profile offline_access roles
   ```

   👉 Without `roles`, Keycloak never puts role claims in the token, so Grafana can’t see them.

---

2. **Role attribute path** –
   You wrote:

   ```yaml
   GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH: contains(roles[*], 'grafana-admin') && 'Admin' || contains(roles[*], 'grafana-editor') && 'Editor' || 'Viewer'
   ```

   But in Keycloak, roles usually appear in `realm_access.roles` or `resource_access.<client_id>.roles`.
   👉 Your expression only checked a flat `roles[]`, which doesn’t exist in the token you showed. That’s why you always fell back to `Viewer`.

---

3. **Grafana Admin mapping** –
   The docs say you need this to elevate a user beyond Org Admin into **Server Admin**:

   ```ini
   allow_assign_grafana_admin = true
   role_attribute_path = contains(roles[*], 'grafanaadmin') && 'GrafanaAdmin' || contains(roles[*], 'admin') && 'Admin' || contains(roles[*], 'editor') && 'Editor' || 'Viewer'
   ```

   👉 Without `allow_assign_grafana_admin`, even if you mapped a role, you’d never get super-admin rights in Grafana.

---

## ✅ Corrected Setup (Docker Compose for Grafana)

Here’s the fixed config for your case:

```yaml
version: "3.9"

services:
  grafana:
    image: grafana/grafana:11.2.0
    container_name: grafana
    restart: unless-stopped
    ports:
      - "3000:3000"
    environment:
      GF_SECURITY_ADMIN_USER: admin
      GF_SECURITY_ADMIN_PASSWORD: admin123
      GF_SERVER_ROOT_URL: http://localhost:3000
      GF_SERVER_DOMAIN: localhost

      # Disable login form (optional)
      GF_AUTH_DISABLE_LOGIN_FORM: "true"

      # OAuth with Keycloak
      GF_AUTH_GENERIC_OAUTH_ENABLED: "true"
      GF_AUTH_GENERIC_OAUTH_NAME: "Keycloak"
      GF_AUTH_GENERIC_OAUTH_ALLOW_SIGN_UP: "true"
      GF_AUTH_GENERIC_OAUTH_CLIENT_ID: "grafana-client"
      GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET: "xxxxxxxxxxxxxxxxxxx"
      GF_AUTH_GENERIC_OAUTH_SCOPES: "openid email profile offline_access roles"
      GF_AUTH_GENERIC_OAUTH_AUTH_URL: "http://keycloak:8080/realms/myrealm/protocol/openid-connect/auth"
      GF_AUTH_GENERIC_OAUTH_TOKEN_URL: "http://keycloak:8080/realms/myrealm/protocol/openid-connect/token"
      GF_AUTH_GENERIC_OAUTH_API_URL: "http://keycloak:8080/realms/myrealm/protocol/openid-connect/userinfo"

      # Role mapping
      GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH: "contains(realm_access.roles[*], 'grafanaadmin') && 'GrafanaAdmin' || contains(realm_access.roles[*], 'grafana-admin') && 'Admin' || contains(realm_access.roles[*], 'grafana-editor') && 'Editor' || 'Viewer'"
      GF_AUTH_GENERIC_OAUTH_ALLOW_ASSIGN_GRAFANA_ADMIN: "true"

    volumes:
      - grafana_data:/var/lib/grafana

volumes:
  grafana_data:
```

---

## ✅ Keycloak Side

1. Create roles in **Realm Roles**:

   * `grafanaadmin` → Grafana Server Admin
   * `grafana-admin` → Org Admin
   * `grafana-editor` → Org Editor
   * `grafana-viewer` → Org Viewer

2. Assign these roles to your users.

3. In your **Grafana client settings**:

   * Default client scopes must include: `email`, `profile`, `roles`, `offline_access`.
   * Add a **mapper**:

     * Type: `User Realm Role`
     * Token Claim Name: `roles` (or leave default → it goes into `realm_access.roles`)
     * Add to **ID token**: ON
     * Add to **Access token**: ON

---

## 🛠 Steps to Verify

1. Log in again via Keycloak in Grafana.
2. Decode the token (with `jq` or jwt.io). You should see:

   ```json
   "realm_access": {
     "roles": [
       "grafana-admin",
       "grafana-editor"
     ]
   }
   ```
3. Grafana should now assign your role according to the mapping.

---

👉 So in summary, your mistake was:

* Missing `roles` in scopes
* Wrong `role_attribute_path` (checking for `roles[*]` instead of `realm_access.roles[*]`)
* Missing `allow_assign_grafana_admin`

---

Would you like me to **write the exact Keycloak “mapper” config step by step in the admin console UI** (with screenshots description) so you can be 100% sure your token contains the roles Grafana expects?
----
___
----




Perfect 👍 thanks for sharing your Grafana config.
Now let’s build the **full Keycloak configuration** side to side so that Grafana’s RBAC (Admin/Editor/Viewer) works properly.

---

## 🔑 Keycloak Configuration for Grafana

We need to configure Keycloak as an **OpenID Connect provider** and send the correct **role claims** in the ID Token that Grafana understands.

---

### 1. Create a Realm (if not existing)

* Go to **Keycloak Admin Console** → `http://localhost:8080/admin`
* Create a new realm (e.g., `grafana-realm`)

---

### 2. Create a Client (for Grafana)

* Navigate: **Clients → Create**
* Client ID: `grafana`
* Protocol: `openid-connect`
* Root URL: `http://localhost:3000/` (Grafana URL)
* Save.

Now configure:

* **Access Type**: `confidential`
* **Valid Redirect URIs**: `http://localhost:3000/*`
* **Web Origins**: `*`
* **Direct Access Grants Enabled**: ON
* Save.

Then → **Credentials** tab → copy **Client Secret** (you already have).

---

### 3. Create Roles

We need roles in Keycloak that map to Grafana’s roles.

* Go to **Roles → Add Role**

  * `grafana-admin`
  * `grafana-editor`
  * `grafana-viewer`

---

### 4. Assign Roles to Users

* Go to **Users → pick your user → Role Mappings**
* Assign one or more of the roles (`grafana-admin`, etc.).

---

### 5. Add Client Role Mapper (Expose roles in Token)

Grafana only works if the JWT from Keycloak has the roles claim.

* Go to: **Clients → grafana → Mappers → Create**
* Name: `realm-roles`
* Mapper Type: **User Realm Role**
* Token Claim Name: `roles`
* Claim JSON Type: `String`
* Add to ID token: ✅
* Add to Access token: ✅

Save.

---

### 6. Optional — Custom Claim for Grafana RBAC

If you want **direct RBAC mapping**:

* Create a new Mapper:

  * Name: `grafana_role`
  * Mapper Type: **User Realm Role**
  * Token Claim Name: `grafana_role`
  * Claim JSON Type: `String`
  * Add to ID token: ✅

This way, Grafana sees a claim `grafana_role: "grafana-admin"` etc.

---

## 📄 Example Keycloak → Token Output

After login, Grafana should get an ID token with something like:

```json
{
  "preferred_username": "reetesh",
  "email": "reetesh@example.com",
  "roles": [
    "grafana-admin"
  ],
  "grafana_role": "grafana-admin"
}
```

---

## 🔗 Grafana side (already you have)

In `grafana.ini` or `docker-compose` config:

```yaml
GF_AUTH_GENERIC_OAUTH_ENABLED: "true"
GF_AUTH_GENERIC_OAUTH_NAME: "Keycloak"
GF_AUTH_GENERIC_OAUTH_CLIENT_ID: "grafana"
GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET: "xxxxxxxx"
GF_AUTH_GENERIC_OAUTH_SCOPES: "openid email profile roles"
GF_AUTH_GENERIC_OAUTH_AUTH_URL: "http://keycloak:8080/realms/grafana-realm/protocol/openid-connect/auth"
GF_AUTH_GENERIC_OAUTH_TOKEN_URL: "http://keycloak:8080/realms/grafana-realm/protocol/openid-connect/token"
GF_AUTH_GENERIC_OAUTH_API_URL: "http://keycloak:8080/realms/grafana-realm/protocol/openid-connect/userinfo"
GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH: "contains(roles[*], 'grafana-admin') && 'Admin' || contains(roles[*], 'grafana-editor') && 'Editor' || 'Viewer'"
GF_AUTH_GENERIC_OAUTH_ALLOW_ASSIGN_GRAFANA_ADMIN: "true"
GF_AUTH_SIGNOUT_REDIRECT_URL: "http://keycloak:8080/realms/grafana-realm/protocol/openid-connect/logout"
```

---

## ✅ Flow

1. User logs in → redirected to Keycloak.
2. Keycloak sends token with `roles`.
3. Grafana parses token and checks `GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH`.
4. User gets correct Grafana role.

---

👉 Now question for you:
Do you want me to also write the **Docker Compose config for Keycloak** (with Postgres DB + realm import JSON for automation), so that when you bring it up, everything is preconfigured?
