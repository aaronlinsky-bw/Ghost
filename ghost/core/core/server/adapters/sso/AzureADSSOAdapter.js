const Base = require('./SSOBase');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const logging = require('@tryghost/logging');
const models = require('../../models');
const security = require('@tryghost/security');

/**
 * Azure AD SSO Adapter for Ghost
 * 
 * Handles OAuth/OIDC authentication with Azure AD (Entra ID) and maps
 * Azure AD groups to Ghost staff roles or member accounts.
 * 
 * Configuration (in config.*.json):
 * {
 *   "adapters": {
 *     "sso": {
 *       "active": "AzureADSSOAdapter",
 *       "AzureADSSOAdapter": {
 *         "tenantId": "your-tenant-id",
 *         "clientId": "your-client-id",
 *         "clientSecret": "your-client-secret",
 *         "staffGroupMapping": {
 *           "AL_Blog_Admin": "Administrator",
 *           "AL_Blog_Author": "Author"
 *         },
 *         "memberGroups": ["AL_Blog_User"]
 *       }
 *     }
 *   }
 * }
 */
class AzureADSSOAdapter extends Base {
    constructor(config = {}) {
        super();
        this.tenantId = config.tenantId;
        this.clientId = config.clientId;
        this.clientSecret = config.clientSecret;
        this.staffGroupMapping = config.staffGroupMapping || {};
        this.memberGroups = config.memberGroups || [];
        // Map Azure AD groups to member labels (e.g., {"Premium-Users": "premium"})
        this.memberGroupMapping = config.memberGroupMapping || {};
        
        // Azure AD endpoints
        this.issuer = `https://login.microsoftonline.com/${this.tenantId}/v2.0`;
        this.jwksUri = `https://login.microsoftonline.com/${this.tenantId}/discovery/v2.0/keys`;
        this.tokenEndpoint = `https://login.microsoftonline.com/${this.tenantId}/oauth2/v2.0/token`;
        this.graphEndpoint = 'https://graph.microsoft.com/v1.0';
        
        // Initialize JWKS client for token verification
        if (this.tenantId) {
            this.jwksClientInstance = jwksClient({
                jwksUri: this.jwksUri,
                cache: true,
                cacheMaxAge: 86400000 // 24 hours
            });
        }
        
        // Cache for user groups (to avoid repeated Graph API calls)
        this._groupCache = new Map();
        this._groupCacheTimeout = 300000; // 5 minutes
    }

    /**
     * Extract credentials from the request
     * Looks for:
     * 1. Authorization header with Bearer token (for API access)
     * 2. OAuth callback with authorization code (for login flow)
     * 3. Session token from cookie
     * 
     * @param {import('express').Request} req
     * @returns {Promise<{type: string, value: string}|null>}
     */
    async getRequestCredentials(req) {
        // Check for Bearer token in Authorization header
        const authHeader = req.get('authorization');
        if (authHeader && authHeader.startsWith('Bearer ')) {
            const token = authHeader.substring(7);
            return {type: 'bearer', value: token};
        }

        // Check for OAuth callback with authorization code
        if (req.query && req.query.code) {
            return {type: 'code', value: req.query.code};
        }

        // Check for id_token in query (implicit flow, not recommended but supported)
        if (req.query && req.query.id_token) {
            return {type: 'id_token', value: req.query.id_token};
        }

        return null;
    }

    /**
     * Validate credentials and extract user identity
     * 
     * @param {{type: string, value: string}} credentials
     * @returns {Promise<{email: string, name: string, groups: string[], azureId: string}|null>}
     */
    async getIdentityFromCredentials(credentials) {
        if (!credentials) {
            return null;
        }

        try {
            let accessToken;
            let idToken;

            if (credentials.type === 'code') {
                // Exchange authorization code for tokens
                const tokens = await this._exchangeCodeForTokens(credentials.value);
                if (!tokens) {
                    return null;
                }
                accessToken = tokens.access_token;
                idToken = tokens.id_token;
            } else if (credentials.type === 'bearer' || credentials.type === 'id_token') {
                // Validate the provided token
                idToken = credentials.value;
                accessToken = credentials.value;
            } else {
                return null;
            }

            // Verify and decode the ID token
            const decoded = await this._verifyToken(idToken);
            if (!decoded) {
                return null;
            }

            // Get user's group memberships from Graph API
            const groups = await this._getUserGroups(accessToken, decoded.oid);

            return {
                email: decoded.email || decoded.preferred_username || decoded.upn,
                name: decoded.name || decoded.given_name || decoded.email,
                groups: groups,
                azureId: decoded.oid
            };
        } catch (err) {
            logging.error({
                message: 'Azure AD SSO: Failed to get identity from credentials',
                err
            });
            return null;
        }
    }

    /**
     * Look up or create a Ghost user based on the Azure AD identity
     * Maps Azure AD groups to Ghost roles for staff, or creates members
     * 
     * @param {{email: string, name: string, groups: string[], azureId: string}} identity
     * @returns {Promise<Object|null>} Ghost user model
     */
    async getUserForIdentity(identity) {
        if (!identity || !identity.email) {
            return null;
        }

        try {
            // Determine what role the user should have based on group membership
            const roleInfo = this._determineRole(identity.groups);

            if (!roleInfo.isStaff && !roleInfo.isMember) {
                logging.warn({
                    message: `Azure AD SSO: User ${identity.email} is not in any configured groups`,
                    context: {groups: identity.groups}
                });
                return null;
            }

            if (roleInfo.isStaff) {
                return await this._getOrCreateStaffUser(identity, roleInfo.roleName);
            }

            // For members, we return null here - member authentication is handled separately
            // The member OAuth flow will handle member creation
            logging.info({
                message: `Azure AD SSO: User ${identity.email} is a member, not staff`
            });
            return null;
        } catch (err) {
            logging.error({
                message: 'Azure AD SSO: Failed to get/create user for identity',
                err,
                context: {email: identity.email}
            });
            return null;
        }
    }

    /**
     * Exchange OAuth authorization code for tokens
     * @private
     */
    async _exchangeCodeForTokens(code) {
        if (!this.clientId || !this.clientSecret || !this.tenantId) {
            logging.error({message: 'Azure AD SSO: Missing configuration (clientId, clientSecret, or tenantId)'});
            return null;
        }

        const redirectUri = this._getRedirectUri();

        const params = new URLSearchParams();
        params.append('client_id', this.clientId);
        params.append('client_secret', this.clientSecret);
        params.append('code', code);
        params.append('redirect_uri', redirectUri);
        params.append('grant_type', 'authorization_code');
        params.append('scope', 'openid profile email User.Read GroupMember.Read.All');

        try {
            const response = await fetch(this.tokenEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: params.toString()
            });

            if (!response.ok) {
                const errorText = await response.text();
                logging.error({
                    message: 'Azure AD SSO: Token exchange failed',
                    context: {status: response.status, error: errorText}
                });
                return null;
            }

            return await response.json();
        } catch (err) {
            logging.error({
                message: 'Azure AD SSO: Token exchange request failed',
                err
            });
            return null;
        }
    }

    /**
     * Verify Azure AD JWT token
     * @private
     */
    async _verifyToken(token) {
        if (!this.jwksClientInstance) {
            logging.error({message: 'Azure AD SSO: JWKS client not initialized'});
            return null;
        }

        return new Promise((resolve) => {
            const getKey = (header, callback) => {
                this.jwksClientInstance.getSigningKey(header.kid, (err, key) => {
                    if (err) {
                        callback(err);
                        return;
                    }
                    const signingKey = key.getPublicKey();
                    callback(null, signingKey);
                });
            };

            jwt.verify(token, getKey, {
                audience: this.clientId,
                issuer: this.issuer,
                algorithms: ['RS256']
            }, (err, decoded) => {
                if (err) {
                    logging.error({
                        message: 'Azure AD SSO: Token verification failed',
                        err
                    });
                    resolve(null);
                    return;
                }
                resolve(decoded);
            });
        });
    }

    /**
     * Get user's group memberships from Microsoft Graph API
     * @private
     */
    async _getUserGroups(accessToken, userId) {
        // Check cache first
        const cacheKey = userId;
        const cached = this._groupCache.get(cacheKey);
        if (cached && Date.now() - cached.timestamp < this._groupCacheTimeout) {
            return cached.groups;
        }

        try {
            // Use memberOf endpoint to get group memberships
            const response = await fetch(`${this.graphEndpoint}/me/memberOf`, {
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                logging.warn({
                    message: 'Azure AD SSO: Failed to fetch user groups from Graph API',
                    context: {status: response.status}
                });
                return [];
            }

            const data = await response.json();
            const groups = (data.value || [])
                .filter(item => item['@odata.type'] === '#microsoft.graph.group')
                .map(group => group.displayName);

            // Cache the result
            this._groupCache.set(cacheKey, {
                groups,
                timestamp: Date.now()
            });

            return groups;
        } catch (err) {
            logging.error({
                message: 'Azure AD SSO: Error fetching user groups',
                err
            });
            return [];
        }
    }

    /**
     * Determine the Ghost role based on Azure AD group membership
     * @private
     */
    _determineRole(groups) {
        if (!groups || !Array.isArray(groups)) {
            return {isStaff: false, isMember: false, roleName: null};
        }

        // Check staff groups first (higher priority)
        for (const groupName of groups) {
            if (this.staffGroupMapping[groupName]) {
                return {
                    isStaff: true,
                    isMember: false,
                    roleName: this.staffGroupMapping[groupName]
                };
            }
        }

        // Check member groups
        for (const groupName of groups) {
            if (this.memberGroups.includes(groupName)) {
                return {
                    isStaff: false,
                    isMember: true,
                    roleName: null
                };
            }
        }

        return {isStaff: false, isMember: false, roleName: null};
    }

    /**
     * Get or create a staff user with the appropriate role
     * @private
     */
    async _getOrCreateStaffUser(identity, roleName) {
        const {email, name} = identity;

        // Try to find existing user by email
        let user = await models.User.findOne({email, status: 'all'});

        if (user) {
            // User exists, update role if needed
            const currentRoles = await user.related('roles').fetch();
            const currentRole = currentRoles.at(0);
            
            if (currentRole && currentRole.get('name') !== roleName && currentRole.get('name') !== 'Owner') {
                // Update role (but never demote Owner)
                logging.info({
                    message: `Azure AD SSO: Updating role for ${email} from ${currentRole.get('name')} to ${roleName}`
                });
                
                const newRole = await models.Role.findOne({name: roleName});
                if (newRole) {
                    await user.roles().updatePivot({}, {role_id: newRole.id});
                    // Refresh user to get updated roles
                    user = await models.User.findOne({email, status: 'all'});
                }
            }

            // Ensure user is active
            if (user.get('status') !== 'active') {
                await models.User.edit({status: 'active'}, {id: user.id});
                user = await models.User.findOne({email, status: 'all'});
            }

            return user;
        }

        // Create new user
        logging.info({
            message: `Azure AD SSO: Creating new staff user ${email} with role ${roleName}`
        });

        const userData = {
            name: name || email.split('@')[0],
            email: email,
            password: security.identifier.uid(50), // Random password (SSO users won't use it)
            roles: [roleName],
            status: 'active'
        };

        try {
            user = await models.User.add(userData, {context: {internal: true}});
            return user;
        } catch (err) {
            logging.error({
                message: 'Azure AD SSO: Failed to create user',
                err,
                context: {email}
            });
            return null;
        }
    }

    /**
     * Get the OAuth redirect URI
     * @private
     */
    _getRedirectUri() {
        // This should match what's configured in Azure AD app registration
        const urlUtils = require('../../../shared/url-utils');
        return urlUtils.urlFor({relativeUrl: '/ghost/api/admin/auth/azure/callback'}, true);
    }

    /**
     * Generate the Azure AD authorization URL for initiating login
     * @param {string} state - CSRF state parameter
     * @returns {string}
     */
    getAuthorizationUrl(state) {
        const redirectUri = this._getRedirectUri();
        const params = new URLSearchParams({
            client_id: this.clientId,
            response_type: 'code',
            redirect_uri: redirectUri,
            response_mode: 'query',
            scope: 'openid profile email User.Read GroupMember.Read.All',
            state: state
        });

        return `https://login.microsoftonline.com/${this.tenantId}/oauth2/v2.0/authorize?${params.toString()}`;
    }
}

module.exports = AzureADSSOAdapter;
