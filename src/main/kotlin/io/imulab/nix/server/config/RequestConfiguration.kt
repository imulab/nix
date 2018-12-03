package io.imulab.nix.server.config

import io.imulab.nix.oauth.client.ClientLookup
import io.imulab.nix.oidc.discovery.Discovery
import io.imulab.nix.oidc.discovery.OidcContext
import io.imulab.nix.oidc.jwk.JsonWebKeySetStrategy
import io.imulab.nix.oidc.request.CachedRequestRepository
import io.imulab.nix.oidc.request.OidcAuthorizeRequestProducer
import io.imulab.nix.oidc.request.RequestObjectAwareOidcAuthorizeRequestProducer
import io.imulab.nix.oidc.request.RequestStrategy
import io.imulab.nix.oidc.validation.OidcResponseTypeValidator
import io.imulab.nix.server.authz.ResumeOidcAuthorizeRequestProducer
import io.imulab.nix.server.authz.repo.OidcAuthorizeRequestRepository
import io.imulab.nix.server.http.SpringHttpClient
import io.imulab.nix.server.oidc.GsonClaimsConverter
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import io.imulab.nix.oauth.request.OAuthRequestProducer

/**
 * This class configures everything related to an OAuth/Oidc request (minus state management).
 */
@Configuration
class RequestConfiguration {

    /**
     * A [RequestStrategy] bean. It is responsible of resolving a request object.
     */
    @Bean
    fun requestStrategy(
        cachedRequestRepository: CachedRequestRepository,
        jwksStrategy: JsonWebKeySetStrategy,
        oidcContext: OidcContext
    ) = RequestStrategy(
        repository = cachedRequestRepository,
        httpClient = SpringHttpClient,
        jsonWebKeySetStrategy = jwksStrategy,
        serverContext = oidcContext
    )

    /**
     * A [OAuthRequestProducer] bean. It is responsible of performing preliminary parsing from raw HTTP
     * request object to a explicitly typed form object. Such object can be used for further operation
     * without having to resort to string based parameter names.
     *
     * In this configuration, we use [ResumeOidcAuthorizeRequestProducer], which had the capability to
     * identify re-entry requests and resume original request with new data. On the occasion of a first
     * entry request, it delegates to [RequestObjectAwareOidcAuthorizeRequestProducer], which has the
     * knowledge to expand encoded request parameters in the `request` or `request_uri` parameter. It
     * again delegates to [OidcAuthorizeRequestProducer] for parameters provided directly from query
     * or form parameters.
     */
    @Bean
    fun requestProducer(
        oidcAuthorizeRequestRepository: OidcAuthorizeRequestRepository,
        discovery: Discovery,
        requestStrategy: RequestStrategy,
        clientLookup: ClientLookup
    ) = ResumeOidcAuthorizeRequestProducer(
        oidcAuthorizeRequestRepository = oidcAuthorizeRequestRepository,
        defaultProducer = RequestObjectAwareOidcAuthorizeRequestProducer(
            discovery = discovery,
            claimsJsonConverter = GsonClaimsConverter,
            requestStrategy = requestStrategy,
            firstPassProducer = OidcAuthorizeRequestProducer(
                lookup = clientLookup,
                claimsJsonConverter = GsonClaimsConverter,
                responseTypeValidator = OidcResponseTypeValidator
            )
        )
    )
}