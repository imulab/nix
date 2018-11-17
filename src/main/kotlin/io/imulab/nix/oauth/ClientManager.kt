package io.imulab.nix.oauth

import io.imulab.astrea.client.ClientManager
import io.imulab.astrea.client.DefaultOAuthClient
import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.crypt.BCryptPasswordEncoder
import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.ResponseType
import io.imulab.astrea.domain.SCOPE_OFFLINE
import io.imulab.astrea.domain.SCOPE_OPENID

class MemoryClientManager: ClientManager {

    override fun getClient(id: String): OAuthClient {
        return DefaultOAuthClient(
            id = id,
            secret = BCryptPasswordEncoder().encode("s3cret").toByteArray(),
            responseTypes = listOf(ResponseType.Code, ResponseType.Token),
            grantTypes = listOf(GrantType.AuthorizationCode, GrantType.Implicit, GrantType.ClientCredentials, GrantType.RefreshToken),
            scopes = listOf(SCOPE_OPENID, SCOPE_OFFLINE, "foo", "bar"),
            redirectUris = listOf("http://localhost:8888/callback"),
            public = false
        )
    }
}