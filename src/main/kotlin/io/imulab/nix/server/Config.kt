package io.imulab.nix.server

import io.imulab.nix.oidc.OidcClientAuthenticationMethodValidator
import io.imulab.nix.oidc.OidcContext
import io.ktor.config.ApplicationConfig
import io.ktor.util.KtorExperimentalAPI
import org.jose4j.jwk.JsonWebKeySet
import java.time.Duration

@UseExperimental(KtorExperimentalAPI::class)
class ServerContext(private val config: ApplicationConfig) : OidcContext {

    override val masterJsonWebKeySet: JsonWebKeySet
        get() = TODO("not implemented, depending to JsonWebKeySetRepository") //To change initializer of created properties use File | Settings | File Templates.

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
}
