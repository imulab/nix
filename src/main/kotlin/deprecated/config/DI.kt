package deprecated.config

import io.imulab.astrea.Astrea
import io.imulab.astrea.client.ClientManager
import io.imulab.astrea.domain.ScopeStrategy
import io.imulab.astrea.domain.StringEqualityScopeStrategy
import io.imulab.astrea.provider.OAuthProvider
import io.imulab.astrea.spi.json.JsonEncoder
import io.imulab.astrea.token.storage.*
import io.imulab.astrea.token.storage.impl.MemoryStorage
import deprecated.astrea.GsonEncoder
import deprecated.astrea.HttpClient
import deprecated.consent.AutoConsentStrategy
import deprecated.consent.ConsentStrategy
import deprecated.oauth.FooBarClientManager
import deprecated.route.AuthorizeRoute
import deprecated.route.TokenRoute
import io.ktor.application.Application
import org.kodein.di.Kodein
import org.kodein.di.erased.bind
import org.kodein.di.erased.instance
import org.kodein.di.erased.singleton

fun Application.appModule(): Kodein.Module {
    return Kodein.Module("app") {
        bind<AuthorizeRoute>() with singleton { AuthorizeRoute() }
        bind<TokenRoute>() with singleton { TokenRoute() }
        bind<io.imulab.astrea.spi.http.HttpClient>() with singleton { HttpClient }
        bind<ScopeStrategy>() with singleton { StringEqualityScopeStrategy }
        bind<JsonEncoder>() with singleton { GsonEncoder }
        bind<ConsentStrategy>() with singleton { AutoConsentStrategy }
        bind<OAuthProvider>() with singleton {
            Astrea.compose(
                bom = Astrea.BOM(
                    issuer = "nix",
                    tokenEndpointUrl = "/oauth/token",
                    scopeStrategy = instance(),
                    jsonEncoder = instance(),
                    authorizeCodeStorage = instance(),
                    accessTokenStorage = instance(),
                    refreshTokenStorage = instance(),
                    tokenRevocationStorage = instance(),
                    oidcRequestStorage = instance(),
                    httpClient = instance(),
                    clientManager = instance()
                ),
                enableOAuthAuthorizeFlow = booleanConfig("flow.oauth.authorize", true),
                enableOAuthClientCredentialsFlow = booleanConfig("flow.oauth.client-credentials", true),
                enableOAuthImplicitFlow = booleanConfig("flow.oauth.implicit", true),
                enableOAuthRefreshFlow = booleanConfig("flow.oauth.refresh", true),
                enableOAuthResourceOwnerFlow = booleanConfig("flow.oauth.resource-owner"),
                enablePkce = false,
                enableOidcAuthorizeFlow = booleanConfig("flow.oidc.authorize"),
                enableOidcHybridFlow = booleanConfig("flow.oidc.hybrid"),
                enableOidcImplicitFlow = booleanConfig("flow.oidc.implicit"),
                enableOidcRefreshFlow = false,
                enableIntrospection = false,
                enableRevocation = false
            )
        }
    }
}

// TODO module of default no-op persistence implementation as base module

fun Application.memoryPersistenceModule(): Kodein.Module {
    val memoryStore = MemoryStorage()
    val fooBarClientManager = FooBarClientManager()
    return Kodein.Module("persistence.memory") {
        bind<AuthorizeCodeStorage>() with singleton { memoryStore }
        bind<AccessTokenStorage>() with singleton { memoryStore }
        bind<RefreshTokenStorage>() with singleton { memoryStore }
        bind<TokenRevocationStorage>() with singleton { memoryStore }
        bind<OpenIdConnectRequestStorage>() with singleton { memoryStore }
        bind<ClientManager>() with singleton { fooBarClientManager }
    }
}