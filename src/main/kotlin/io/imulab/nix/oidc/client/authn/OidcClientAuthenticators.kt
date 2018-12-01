package io.imulab.nix.oidc.client.authn

import io.imulab.nix.oauth.*
import io.imulab.nix.oauth.client.authn.ClientAuthenticator
import io.imulab.nix.oauth.client.authn.ClientAuthenticators
import io.imulab.nix.oauth.client.ClientLookup
import io.imulab.nix.oidc.client.OidcClient

/**
 * Simple override of [ClientAuthenticators] to use the client pre-registered value of token endpoint authentication
 * method as the actual authentication method, instead of a default fixed one determined by the server.
 */
class OidcClientAuthenticators(
    authenticators: List<ClientAuthenticator>,
    private val clientLookup: ClientLookup
) : ClientAuthenticators(
    authenticators = authenticators,
    methodFinder = { f ->
        clientLookup.find(f.clientId)
            .assertType<OidcClient>()
            .tokenEndpointAuthenticationMethod
    }
)