const express = require('../../../shared/express');
const logging = require('@tryghost/logging');
const security = require('@tryghost/security');
const urlUtils = require('../../../shared/url-utils');
const adapterManager = require('../../services/adapter-manager');
const membersService = require('../../services/members');
const config = require('../../../shared/config');

/**
 * Get the Azure AD SSO adapter if configured for members
 * @returns {Object|null}
 */
function getAzureAdapter() {
    try {
        const adapter = adapterManager.getAdapter('sso');
        // Check if it's the Azure AD adapter (has getAuthorizationUrl method)
        if (adapter && typeof adapter.getAuthorizationUrl === 'function') {
            return adapter;
        }
        return null;
    } catch (err) {
        logging.warn({message: 'Azure AD SSO adapter not available for members', err});
        return null;
    }
}

/**
 * Check if user's groups include any member groups
 * @param {Object} adapter 
 * @param {string[]} groups 
 * @returns {boolean}
 */
function isMemberGroup(adapter, groups) {
    const memberGroups = adapter.memberGroups || [];
    return groups.some(group => memberGroups.includes(group));
}

/**
 * @returns {import('express').Router}
 */
module.exports = function memberAzureAuthRouter() {
    const router = express.Router();

    /**
     * Check if Azure AD SSO is available for members
     */
    router.get('/status', async (req, res) => {
        const adapter = getAzureAdapter();
        const adapterConfig = config.get('adapters:sso');
        
        res.json({
            enabled: adapter !== null && adapterConfig.active === 'AzureADSSOAdapter',
            configured: adapter !== null && adapter.tenantId && adapter.clientId && adapter.memberGroups?.length > 0
        });
    });

    /**
     * Initiate Azure AD OAuth login for members
     */
    router.get('/redirect', async (req, res) => {
        const adapter = getAzureAdapter();

        if (!adapter) {
            return res.status(404).json({
                errors: [{message: 'Azure AD SSO is not configured for members'}]
            });
        }

        // Generate CSRF state token with member marker
        const state = `member_${security.identifier.uid(32)}`;

        // Store state in session
        if (!req.session) {
            req.session = {};
        }
        req.session.azureMemberOAuthState = state;

        // Store the redirect URL if provided
        if (req.query.redirect) {
            req.session.azureMemberRedirect = req.query.redirect;
        }

        // Generate authorization URL with member-specific redirect
        const redirectUri = urlUtils.urlFor({relativeUrl: '/members/api/auth/azure/callback'}, true);
        
        const params = new URLSearchParams({
            client_id: adapter.clientId,
            response_type: 'code',
            redirect_uri: redirectUri,
            response_mode: 'query',
            scope: 'openid profile email User.Read GroupMember.Read.All',
            state: state
        });

        const authUrl = `https://login.microsoftonline.com/${adapter.tenantId}/oauth2/v2.0/authorize?${params.toString()}`;
        res.redirect(authUrl);
    });

    /**
     * Handle Azure AD OAuth callback for members
     */
    router.get('/callback', async (req, res) => {
        const adapter = getAzureAdapter();
        const siteUrl = urlUtils.getSiteUrl();

        if (!adapter) {
            return res.redirect(`${siteUrl}#/portal/signin?error=sso_not_configured`);
        }

        // Check for OAuth error response
        if (req.query.error) {
            logging.error({
                message: 'Azure AD Member OAuth error',
                context: {
                    error: req.query.error,
                    description: req.query.error_description
                }
            });
            return res.redirect(`${siteUrl}#/portal/signin?error=oauth_error`);
        }

        // Verify state parameter (CSRF protection)
        const returnedState = req.query.state;
        const savedState = req.session?.azureMemberOAuthState;

        if (!returnedState || returnedState !== savedState || !returnedState.startsWith('member_')) {
            logging.warn({
                message: 'Azure AD Member OAuth state mismatch',
                context: {returned: returnedState, saved: savedState}
            });
            return res.redirect(`${siteUrl}#/portal/signin?error=invalid_state`);
        }

        // Clear the state from session
        const redirectUrl = req.session?.azureMemberRedirect || siteUrl;
        if (req.session) {
            delete req.session.azureMemberOAuthState;
            delete req.session.azureMemberRedirect;
        }

        try {
            // Get credentials from request (the authorization code)
            const credentials = await adapter.getRequestCredentials(req);
            if (!credentials) {
                logging.warn({message: 'No credentials found in Azure AD member callback'});
                return res.redirect(`${siteUrl}#/portal/signin?error=no_credentials`);
            }

            // Override the redirect URI for token exchange
            const originalGetRedirectUri = adapter._getRedirectUri;
            adapter._getRedirectUri = () => urlUtils.urlFor({relativeUrl: '/members/api/auth/azure/callback'}, true);

            // Exchange code for tokens and get user identity
            const identity = await adapter.getIdentityFromCredentials(credentials);
            
            // Restore original redirect URI
            adapter._getRedirectUri = originalGetRedirectUri;

            if (!identity) {
                logging.warn({message: 'Failed to get identity from Azure AD member credentials'});
                return res.redirect(`${siteUrl}#/portal/signin?error=auth_failed`);
            }

            // Check if user is in a member group
            if (!isMemberGroup(adapter, identity.groups)) {
                logging.warn({
                    message: 'User not in any member group',
                    context: {email: identity.email, groups: identity.groups}
                });
                return res.redirect(`${siteUrl}#/portal/signin?error=not_authorized`);
            }

            // Get or create member with label mapping from Azure AD groups
            const member = await getOrCreateMember(identity, adapter);
            if (!member) {
                logging.error({message: 'Failed to create/get member for Azure AD user'});
                return res.redirect(`${siteUrl}#/portal/signin?error=member_error`);
            }

            // Create member session
            await membersService.ssr.setMemberSessionCookie(req, res, member);

            logging.info({message: `Azure AD SSO: Member ${identity.email} logged in successfully`});
            return res.redirect(redirectUrl);
        } catch (err) {
            logging.error({
                message: 'Azure AD Member OAuth callback error',
                err
            });
            return res.redirect(`${siteUrl}#/portal/signin?error=callback_error`);
        }
    });

    return router;
};

/**
 * Map Azure AD groups to member labels based on configuration
 * @param {Object} adapter - The Azure AD adapter
 * @param {string[]} groups - User's Azure AD groups
 * @returns {Array<{name: string}>} - Array of label objects for the member
 */
function mapGroupsToLabels(adapter, groups) {
    const labels = [{name: 'Azure AD SSO'}]; // Always add Azure AD SSO label
    
    // Get group-to-label mapping from adapter config
    const memberGroupMapping = adapter.memberGroupMapping || {};
    
    for (const groupName of groups) {
        // Check if there's a specific label mapping for this group
        if (memberGroupMapping[groupName]) {
            labels.push({name: memberGroupMapping[groupName]});
        }
    }
    
    return labels;
}

/**
 * Get or create a member from Azure AD identity
 * @param {{email: string, name: string, groups: string[], azureId: string}} identity
 * @param {Object} adapter - The Azure AD adapter for config access
 * @returns {Promise<Object|null>}
 */
async function getOrCreateMember(identity, adapter) {
    const {email, name, groups} = identity;
    
    // Map Azure AD groups to member labels
    const labels = mapGroupsToLabels(adapter, groups);
    
    try {
        const membersApi = await membersService.api;
        
        // Try to find existing member
        let member = await membersApi.members.get({email});
        
        if (member) {
            logging.info({message: `Azure AD SSO: Found existing member ${email}`});
            
            // Update labels on existing member to sync with Azure AD groups
            try {
                const existingLabels = member.labels || [];
                const existingLabelNames = existingLabels.map(l => l.name);
                
                // Merge labels: keep existing + add new from Azure AD
                const mergedLabels = [...existingLabels];
                for (const label of labels) {
                    if (!existingLabelNames.includes(label.name)) {
                        mergedLabels.push(label);
                    }
                }
                
                // Update member with merged labels
                member = await membersApi.members.update({labels: mergedLabels}, {id: member.id});
                logging.info({
                    message: `Azure AD SSO: Updated member labels for ${email}`,
                    context: {labels: mergedLabels.map(l => l.name)}
                });
            } catch (updateErr) {
                logging.warn({
                    message: 'Azure AD SSO: Failed to update member labels',
                    err: updateErr,
                    context: {email}
                });
            }
            
            return member;
        }

        // Create new member with labels from Azure AD groups
        logging.info({
            message: `Azure AD SSO: Creating new member ${email}`,
            context: {labels: labels.map(l => l.name)}
        });
        
        member = await membersApi.members.create({
            email: email,
            name: name || email.split('@')[0],
            labels: labels
        });

        return member;
    } catch (err) {
        logging.error({
            message: 'Azure AD SSO: Failed to get/create member',
            err,
            context: {email}
        });
        return null;
    }
}
