'use strict';

const Url = require('url');
const { Issuer, generators } = require('openid-client');
const Hoek = require('@hapi/hoek');

const Scheme = require('./scheme');
const Pkg = require('../package.json');

const PLUGIN_DEFAULTS = {
    cookie: 'hapi-oidc',
    scope: 'openid email profile'
};

const COOKIE_DEFAULTS = {
    ignoreErrors: true,
    isSameSite: 'Lax',
    isHttpOnly: true,
    path: '/',
    ttl: 3600 * 1000,
    encoding: 'base64json',
    isSecure: false,
    clearInvalid: true
};

exports.plugin = {
    pkg: Pkg,
    dependencies: ['@biker/hapi-auth-keycloak'],
    register: async (server, options) => {

        const config = Hoek.applyToDefaults(PLUGIN_DEFAULTS, options);

        // todo: Validate config
        const cookieName = config.cookie;
        server.state(cookieName, COOKIE_DEFAULTS);

        const keycloakIssuer = config.discoverUrl ? await Issuer.discover(config.discoverUrl) : new Issuer({
            issuer: config.issuer,
            authorization_endpoint: config.authorization,
            token_endpoint: config.token,
            userinfo_endpoint: config.userinfo,
            jwks_uri: config.jwks
        });

        const client = new keycloakIssuer.Client({
            client_id: config.clientId,
            client_secret: config.clientSecret,
            response_types: ['code'],
            redirect_uris: [`${config.callbackUrl}`]
        });

        const code_verifier = generators.codeVerifier(); //todo: codeIdentifier should be created in "authenticate"

        server.route({
            method: 'GET',
            options: {
                auth: false
            },
            path: Url.parse(config.callbackUrl).path,
            handler: async (request, h) => {

                try {
                    request.log(['auth', 'oidc', 'debug'], 'Callback handler');

                    const params = client.callbackParams(request.raw.req);
                    const tokenSet = await client.callback(config.callbackUrl, params, {
                        code_verifier,
                        state: params.state
                    });

                    request.log(['auth', 'oidc', 'debug'], `redirect to state ${params.state}`);
                    return h.redirect(params.state).state(cookieName, tokenSet.access_token);
                } catch (err) {
                    request.log(['error', 'auth', 'oidc'], err);
                    throw err;
                }
            }
        });

        server.auth.scheme('oidc', Scheme({
            cookieName, scope: config.scope, client, code_verifier
        }));
    }
};
