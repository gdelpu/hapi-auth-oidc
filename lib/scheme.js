'use strict';

const Boom = require('@hapi/boom');

const { generators } = require('openid-client');

// eslint-disable-next-line @hapi/hapi/no-arrowception
module.exports = ({ cookieName, scope = 'openid email profile', client, code_verifier }) =>

    (server, schemeOptions) => {

        return {
            authenticate: async(request, h) => {

                const oidc = request.state[cookieName];
                if (oidc) {
                    try {
                        //Validate token against the default strategy defined in Hapi-Auth-Keycloak plugin
                        const validationResult = await request.server.kjwt.validate(`bearer ${oidc}`, 'default');

                        return validationResult === false ? h.unauthenticated(Boom.unauthorized('invalid token')) : h.authenticated(validationResult);
                    } catch (e) {
                        request.log(['oidc', 'error', 'auth'], e);
                        h.unstate(cookieName); //todo Refresh token would be better.
                        return h.unauthenticated(e);
                    }
                }

                const code_challenge = generators.codeChallenge(code_verifier);
                const redirectUrl = client.authorizationUrl({
                    scope,
                    resource: request.uri,
                    code_challenge,
                    code_challenge_method: 'S256',
                    state: request.path
                });

                return h.redirect(redirectUrl).takeover();
            }
        };
    };
