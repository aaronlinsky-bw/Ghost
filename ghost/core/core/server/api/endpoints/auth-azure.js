const errors = require('@tryghost/errors');
const tpl = require('@tryghost/tpl');
const logging = require('@tryghost/logging');
const security = require('@tryghost/security');
const adapterManager = require('../../services/adapter-manager');
const auth = require('../../services/auth');
const urlUtils = require('../../../shared/url-utils');
const config = require('../../../shared/config');

const messages = {
    ssoNotConfigured: 'Azure AD SSO is not configured'
};

/**
 * Get the Azure AD SSO adapter if configured
 * @returns {Object|null}
 */
function getAzureAdapter() {
    try {
        const adapter = adapterManager.getAdapter('sso');
        if (adapter && typeof adapter.getAuthorizationUrl === 'function') {
            return adapter;
        }
        return null;
    } catch (err) {
        logging.warn({message: 'Azure AD SSO adapter not available', err});
        return null;
    }
}

/**
 * Get SSO status info
 */
function getSsoStatus() {
    const adapter = getAzureAdapter();
    const adapterConfig = config.get('adapters:sso') || {};
    return {
        enabled: adapter !== null && adapterConfig.active === 'AzureADSSOAdapter',
        configured: adapter !== null && adapter.tenantId && adapter.clientId
    };
}

/**
 * Create redirect middleware for OAuth flow
 */
function createRedirectMiddleware(adapter, state) {
    return function redirectMiddleware(req, res) {
        if (!req.session) {
            req.session = {};
        }
        req.session.azureOAuthState = state;
        const authUrl = adapter.getAuthorizationUrl(state);
        res.redirect(authUrl);
    };
}

/**
 * Handle OAuth callback logic
 */
async function handleOAuthCallback(req, res, adapter) {
    const adminUrl = urlUtils.urlFor('admin', true);

    // Check for OAuth error response
    if (req.query.error) {
        logging.error({
            message: 'Azure AD OAuth error',
            context: {error: req.query.error, description: req.query.error_description}
        });
        return res.redirect(`${adminUrl}#/signin?error=oauth_error`);
    }

    // Verify state parameter (CSRF protection)
    const returnedState = req.query.state;
    const savedState = req.session?.azureOAuthState;

    if (!returnedState || returnedState !== savedState) {
        logging.warn({message: 'Azure AD OAuth state mismatch'});
        return res.redirect(`${adminUrl}#/signin?error=invalid_state`);
    }

    // Clear the state from session
    if (req.session) {
        delete req.session.azureOAuthState;
    }

    try {
        const credentials = await adapter.getRequestCredentials(req);
        if (!credentials) {
            return res.redirect(`${adminUrl}#/signin?error=no_credentials`);
        }

        const identity = await adapter.getIdentityFromCredentials(credentials);
        if (!identity) {
            return res.redirect(`${adminUrl}#/signin?error=auth_failed`);
        }

        const user = await adapter.getUserForIdentity(identity);
        if (!user) {
            logging.warn({message: 'User not authorized', context: {email: identity.email}});
            return res.redirect(`${adminUrl}#/signin?error=not_authorized`);
        }

        req.user = user;
        req.skipVerification = true;

        auth.session.createSession(req, res, (err) => {
            if (err) {
                logging.error({message: 'Failed to create session', err});
                return res.redirect(`${adminUrl}#/signin?error=session_failed`);
            }
            logging.info({message: `Azure AD SSO: User ${identity.email} logged in`});
            return res.redirect(adminUrl);
        });
    } catch (err) {
        logging.error({message: 'Azure AD OAuth callback error', err});
        return res.redirect(`${adminUrl}#/signin?error=callback_error`);
    }
}

/** @type {import('@tryghost/api-framework').Controller} */
const controller = {
    docName: 'auth_azure',

    status: {
        headers: {cacheInvalidate: false},
        permissions: false,
        query() {
            return getSsoStatus();
        }
    },

    redirect: {
        headers: {cacheInvalidate: false},
        permissions: false,
        query() {
            const adapter = getAzureAdapter();
            if (!adapter) {
                return Promise.reject(new errors.NotFoundError({
                    message: tpl(messages.ssoNotConfigured)
                }));
            }
            const state = security.identifier.uid(32);
            return Promise.resolve(createRedirectMiddleware(adapter, state));
        }
    },

    callback: {
        headers: {cacheInvalidate: false},
        permissions: false,
        query() {
            return Promise.resolve(async function callbackMiddleware(req, res) {
                const adapter = getAzureAdapter();
                if (!adapter) {
                    return res.redirect(urlUtils.urlFor('admin', true) + '#/signin?error=sso_not_configured');
                }
                await handleOAuthCallback(req, res, adapter);
            });
        }
    }
};

module.exports = controller;
