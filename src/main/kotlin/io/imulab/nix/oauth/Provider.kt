package io.imulab.nix.oauth

import io.imulab.astrea.Astrea
import io.imulab.astrea.domain.StringEqualityScopeStrategy
import io.imulab.astrea.provider.OAuthProvider
import io.imulab.astrea.token.storage.impl.MemoryStorage
import io.imulab.nix.astrea.GsonEncoder
import io.imulab.nix.astrea.HttpClient
import io.ktor.application.Application

fun Application.provider(): OAuthProvider {
    val memoryStore = MemoryStorage()
    val clientStore = MemoryClientManager()

    return Astrea.compose(
        bom = Astrea.BOM(
            issuer = "nix",
            tokenEndpointUrl = "/oauth/token",
            scopeStrategy = StringEqualityScopeStrategy,
            jsonEncoder = GsonEncoder,
            authorizeCodeStorage = memoryStore,
            accessTokenStorage = memoryStore,
            refreshTokenStorage = memoryStore,
            tokenRevocationStorage = memoryStore,
            httpClient = HttpClient,
            clientManager = clientStore
        ),
        enableOAuthAuthorizeFlow = true,
        enableOAuthClientCredentialsFlow = true,
        enableOAuthImplicitFlow = true,
        enableOAuthRefreshFlow = true,
        enableOAuthResourceOwnerFlow = false,
        enablePkce = false,
        enableOidcAuthorizeFlow = false,
        enableOidcHybridFlow = false,
        enableOidcImplicitFlow = false,
        enableOidcRefreshFlow = false,
        enableIntrospection = false,
        enableRevocation = false
    )
}