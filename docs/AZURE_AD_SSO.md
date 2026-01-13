# Azure AD (Entra ID) SSO Integration

This document describes the Azure AD Single Sign-On implementation for Ghost, enabling both staff and member authentication via Microsoft Entra ID.

## Architecture Overview

The SSO system uses Ghost's existing adapter pattern for extensibility:

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Azure AD      │────▶│  SSO Adapter     │────▶│  Ghost User/    │
│   (Entra ID)    │     │  (AzureADSSO)    │     │  Member DB      │
└─────────────────┘     └──────────────────┘     └─────────────────┘
        │                        │
        │                        ▼
        │               ┌──────────────────┐
        │               │  Group Mapping   │
        │               │  - Staff → Roles │
        │               │  - Member→Labels │
        │               └──────────────────┘
        │
        ▼
┌─────────────────┐
│  Microsoft      │
│  Graph API      │
│  (Groups)       │
└─────────────────┘
```

## File Structure

### Core SSO Adapter

**`ghost/core/core/server/adapters/sso/AzureADSSOAdapter.js`**

The main SSO adapter that implements the OAuth/OIDC flow:

- `getRequestCredentials(req)` - Extracts OAuth code or bearer token from request
- `getIdentityFromCredentials(credentials)` - Exchanges code for tokens, validates JWT, fetches user info and groups
- `getUserForIdentity(identity)` - Looks up or creates Ghost user with appropriate role
- `getAuthorizationUrl(state)` - Generates Azure AD authorization URL
- `_verifyToken(token)` - Validates JWT using Azure AD JWKS
- `_getUserGroups(accessToken)` - Fetches group memberships from Microsoft Graph API
- `_determineRole(groups)` - Maps Azure AD groups to Ghost roles
- `_getOrCreateStaffUser(identity, roleName)` - Provisions staff users

### Staff Authentication (Admin Panel)

**`ghost/core/core/server/api/endpoints/auth-azure.js`**

API controller for staff SSO:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ghost/api/admin/auth/azure/status` | GET | Returns SSO configuration status |
| `/ghost/api/admin/auth/azure/redirect` | GET | Initiates OAuth flow, redirects to Azure AD |
| `/ghost/api/admin/auth/azure/callback` | GET | Handles OAuth callback, creates session |

**`ghost/core/core/server/api/endpoints/index.js`**
- Registers the `authAzure` endpoint

**`ghost/core/core/server/web/api/endpoints/admin/routes.js`**
- Adds the three Azure AD routes to the admin API

### Member Authentication (Portal)

**`ghost/core/core/server/web/members/azure-auth.js`**

Express router for member SSO:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/members/api/auth/azure/status` | GET | Returns member SSO status |
| `/members/api/auth/azure/redirect` | GET | Initiates member OAuth flow |
| `/members/api/auth/azure/callback` | GET | Handles callback, creates member session |

Key functions:
- `getOrCreateMember(identity, adapter)` - Creates or updates member with labels from Azure AD groups
- `mapGroupsToLabels(adapter, groups)` - Converts Azure AD groups to Ghost member labels

**`ghost/core/core/server/web/members/app.js`**
- Mounts the azure-auth router at `/api/auth/azure`

### Admin Settings UI

**`apps/admin-x-settings/src/components/settings/advanced/integrations/azure-ad-modal.tsx`**

React component showing:
- SSO configuration status (enabled/configured)
- Configuration instructions with JSON example
- Azure Portal setup steps
- SSO login URL when configured

**`apps/admin-x-settings/src/components/settings/advanced/integrations.tsx`**
- Adds Azure AD SSO to the integrations list

**`apps/admin-x-settings/src/components/providers/settings-router.tsx`**
- Adds route `integrations/azure-ad` → `AzureADModal`

**`apps/admin-x-settings/src/components/providers/routing/modals.tsx`**
- Registers the AzureADModal component

### Portal UI

**`apps/portal/src/components/pages/signin-page.js`**

Modified signin page that:
- Checks `/members/api/auth/azure/status` on mount
- Renders "Sign in with Microsoft" button when SSO is configured
- Includes divider between SSO and email login

**`apps/portal/src/actions.js`**
- Adds `signinWithMicrosoft` action that redirects to SSO endpoint

**`apps/portal/src/images/icons/microsoft.svg`**
- Microsoft logo icon for the SSO button

## Configuration

Add to your Ghost config file (e.g., `config.production.json`):

```json
{
  "adapters": {
    "sso": {
      "active": "AzureADSSOAdapter",
      "AzureADSSOAdapter": {
        "tenantId": "your-azure-tenant-id",
        "clientId": "your-app-client-id",
        "clientSecret": "your-client-secret",
        "staffGroupMapping": {
          "AL_Blog_Admin": "Administrator",
          "AL_Blog_Author": "Author"
        },
        "memberGroups": ["AL_Blog_User"],
        "memberGroupMapping": {
          "AL_Blog_User": "Azure SSO User"
        }
      }
    }
  }
}
```

### Configuration Options

| Option | Type | Description |
|--------|------|-------------|
| `tenantId` | string | Azure AD tenant ID (from Azure Portal) |
| `clientId` | string | Application (client) ID from app registration |
| `clientSecret` | string | Client secret from app registration |
| `staffGroupMapping` | object | Maps Azure AD group names to Ghost roles |
| `memberGroups` | array | List of groups that grant member access |
| `memberGroupMapping` | object | Maps Azure AD groups to member labels |

### Ghost Role Options

Staff roles that can be assigned via `staffGroupMapping`:
- `Administrator` - Full admin access
- `Super Editor` - Can manage all content
- `Editor` - Can manage posts by all authors
- `Author` - Can create and publish own posts
- `Contributor` - Can create drafts only

## Azure AD App Registration Setup

1. Go to **Azure Portal** → **Microsoft Entra ID** → **App registrations**
2. Click **New registration**
3. Name your application (e.g., "Ghost SSO")
4. Set **Supported account types** based on your needs
5. Add **Redirect URIs**:
   - `https://your-site.com/ghost/api/admin/auth/azure/callback` (for staff)
   - `https://your-site.com/members/api/auth/azure/callback` (for members)
6. Go to **Certificates & secrets** → Create a new client secret
7. Go to **API permissions** → Add permissions:
   - `Microsoft Graph` → `User.Read` (delegated)
   - `Microsoft Graph` → `GroupMember.Read.All` (delegated)
8. Grant admin consent if required
9. Note your **Tenant ID**, **Client ID**, and **Client Secret**

## Group-to-Role Mapping

### How it works

1. User signs in via Azure AD
2. Ghost fetches user's group memberships from Microsoft Graph API
3. Groups are matched against `staffGroupMapping` (for staff) or `memberGroups` (for members)
4. First matching staff group determines the Ghost role
5. For members, all matching groups in `memberGroupMapping` become labels

### Example

With this configuration:
```json
{
  "staffGroupMapping": {
    "Ghost-Admins": "Administrator",
    "Ghost-Authors": "Author"
  },
  "memberGroups": ["Ghost-Readers"],
  "memberGroupMapping": {
    "Ghost-Readers": "SSO Reader",
    "Premium-Users": "Premium"
  }
}
```

- User in `Ghost-Admins` → Staff with Administrator role
- User in `Ghost-Authors` → Staff with Author role
- User in `Ghost-Readers` → Member with "SSO Reader" label
- User in `Ghost-Readers` AND `Premium-Users` → Member with both labels

## Testing

### 1. Check SSO Status

```bash
# Staff SSO status
curl http://localhost:2368/ghost/api/admin/auth/azure/status

# Member SSO status
curl http://localhost:2368/members/api/auth/azure/status
```

Expected response when configured:
```json
{"enabled": true, "configured": true}
```

### 2. Test Staff Login

Navigate to:
```
http://localhost:2368/ghost/api/admin/auth/azure/redirect
```

This redirects to Microsoft login. After authentication, you'll be redirected back to Ghost Admin.

### 3. Test Member Login

1. Open Portal signin page
2. Look for "Sign in with Microsoft" button
3. Click and authenticate
4. Verify member is created with correct labels

### 4. Verify User Creation

- **Staff**: Check Settings → Staff in Ghost Admin
- **Members**: Check Members section in Ghost Admin

## Security Considerations

- **CSRF Protection**: OAuth state parameter prevents CSRF attacks
- **Token Validation**: JWTs are validated using Azure AD's public keys (JWKS)
- **Group Caching**: User groups are cached for 5 minutes to reduce API calls
- **MFA Support**: Azure AD handles MFA; Ghost skips device verification for SSO users
- **Secret Storage**: Client secret should be in config file, not database

## Dependencies

These packages are already included in Ghost:
- `jsonwebtoken` - JWT validation
- `jwks-rsa` - Fetches Azure AD public keys for token verification

## Troubleshooting

### "SSO is not configured" error
- Check that `adapters.sso.active` is set to `AzureADSSOAdapter`
- Verify tenantId, clientId, and clientSecret are correct

### "User not authorized" error
- User is not in any configured staff or member group
- Check group names match exactly (case-sensitive)

### "Token verification failed" error
- Verify clientId matches the Azure AD app registration
- Check tenantId is correct

### No "Sign in with Microsoft" button
- Rebuild Portal: `yarn build` in apps/portal
- Verify memberGroups has at least one group configured
