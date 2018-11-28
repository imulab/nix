package io.imulab.nix.server

import io.imulab.nix.oauth.StateValidator
import io.imulab.nix.oidc.JsonWebKeySetRepository
import io.imulab.nix.oidc.NonceValidator
import io.imulab.nix.oidc.OidcClientAuthenticationMethodValidator
import io.imulab.nix.oidc.OidcContext
import io.imulab.nix.server.route.AuthorizeRouteProvider
import io.ktor.config.ApplicationConfig
import io.ktor.util.KtorExperimentalAPI
import kotlinx.coroutines.runBlocking
import org.jose4j.jwk.JsonWebKeySet
import org.kodein.di.Kodein
import org.kodein.di.erased.bind
import org.kodein.di.erased.instance
import org.kodein.di.erased.singleton
import java.time.Duration

/**
 * Global server configuration
 */
@UseExperimental(KtorExperimentalAPI::class)
class ServerContext(
    private val config: ApplicationConfig,
    private val jsonWebKeySetRepository: JsonWebKeySetRepository
) : OidcContext {

    override val masterJsonWebKeySet: JsonWebKeySet by lazy {
        runBlocking { jsonWebKeySetRepository.getServerJsonWebKeySet() }
    }

    override val masterJsonWebKeySetUrl: String by lazy {
        config.stringPropertyOrNull("nix.endpoint.jwks")
            ?: throw IllegalStateException("config <nix.endpoint.jwks> must be set.")
    }

    override val issuerUrl: String by lazy {
        config.stringPropertyOrNull("nix.endpoint.issuer")
            ?: throw IllegalStateException("config <nix.endpoint.issuer> must be set.")
    }

    override val authorizeEndpointUrl: String by lazy {
        config.stringPropertyOrNull("nix.endpoint.authorize")
            ?: throw IllegalStateException("config <nix.endpoint.authorize> must be set.")
    }

    override val tokenEndpointUrl: String by lazy {
        config.stringPropertyOrNull("nix.endpoint.token")
            ?: throw IllegalStateException("config <nix.endpoint.token> must be set.")
    }

    override val defaultTokenEndpointAuthenticationMethod: String by lazy {
        config.stringPropertyOrNull("nix.endpoint.security.tokenEndpointAuth")
            ?.let { OidcClientAuthenticationMethodValidator.validate(it) }
            ?: throw IllegalStateException("config <nix.endpoint.security.tokenEndpointAuth> must be set.")
    }

    override val authorizeCodeLifespan: Duration by lazy {
        config.longPropertyOrNull("nix.token.authorizeCodeExpirationSeconds").let {
            if (it == null)
                Duration.ofMinutes(10)
            else
                Duration.ofSeconds(it)
        }
    }

    override val accessTokenLifespan: Duration by lazy {
        config.longPropertyOrNull("nix.token.accessTokenExpirationSeconds").let {
            if (it == null)
                Duration.ofDays(1)
            else
                Duration.ofSeconds(it)
        }
    }

    override val refreshTokenLifespan: Duration by lazy {
        config.longPropertyOrNull("nix.token.refreshTokenExpirationSeconds").let {
            if (it == null)
                Duration.ofDays(14)
            else
                Duration.ofSeconds(it)
        }
    }

    override val idTokenLifespan: Duration by lazy {
        config.longPropertyOrNull("nix.token.idTokenExpirationSeconds").let {
            if (it == null)
                Duration.ofDays(1)
            else
                Duration.ofSeconds(it)
        }
    }

    override val nonceEntropy: Int by lazy {
        config.intPropertyOrNull("nix.param.nonceEntropy") ?: 0
    }


    override val stateEntropy: Int by lazy {
        config.intPropertyOrNull("nix.param.stateEntropy") ?: 0
    }
}

/**
 * Declare dependency injection modules.
 */
object DependencyInjection {

    val validators = Kodein.Module(name = "validators") {
        bind() from singleton { StateValidator(oauthContext = instance()) }
        bind() from singleton { NonceValidator(oidcContext = instance()) }
    }

    val routeProviders = Kodein.Module(name = "routeProviders") {
        bind() from singleton {
            AuthorizeRouteProvider(
                requestProducer = instance("TODO")
            )
        }
    }
}