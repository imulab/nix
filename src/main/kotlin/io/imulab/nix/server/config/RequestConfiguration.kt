package io.imulab.nix.server.config

import com.fasterxml.jackson.databind.ObjectMapper
import io.imulab.nix.oauth.client.ClientLookup
import io.imulab.nix.oauth.client.authn.ClientAuthenticators
import io.imulab.nix.oauth.request.OAuthAccessRequestProducer
import io.imulab.nix.oauth.validation.OAuthGrantTypeValidator
import io.imulab.nix.oidc.jwk.JsonWebKeySetStrategy
import io.imulab.nix.oidc.request.*
import io.imulab.nix.oidc.validation.OidcResponseTypeValidator
import io.imulab.nix.server.authz.ResumeOidcAuthorizeRequestProducer
import io.imulab.nix.server.authz.repo.MemoryOidcAuthorizeRequestRepository
import io.imulab.nix.server.authz.repo.OidcAuthorizeRequestRepository
import io.imulab.nix.server.http.SpringHttpClient
import io.imulab.nix.server.oidc.JacksonClaimConverter
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

/**
 * This class configures everything related to an OAuth/Oidc request (minus state management).
 */
@Configuration
class RequestConfiguration @Autowired constructor(
    private val properties: NixProperties,
    private val jsonWebKeySetStrategy: JsonWebKeySetStrategy,
    private val clientLookup: ClientLookup,
    private val clientAuthenticators: ClientAuthenticators,
    private val objectMapper: ObjectMapper
) {

    @Bean @Memory
    fun memoryOidcAuthorizeRequestRepository() = MemoryOidcAuthorizeRequestRepository()

    @Bean @Memory
    fun memoryCachedRequestRepository() = MemoryCachedRequestRepository()

    @Bean
    fun requestStrategy(repository: CachedRequestRepository) = RequestStrategy(
        repository = repository,
        httpClient = SpringHttpClient,
        jsonWebKeySetStrategy = jsonWebKeySetStrategy,
        serverContext = properties
    )

    @Bean("authorizeRequestProducer")
    fun authorizeRequestProducer(arRepo: OidcAuthorizeRequestRepository, requestStrategy: RequestStrategy) =
        ResumeOidcAuthorizeRequestProducer(
            oidcAuthorizeRequestRepository = arRepo,
            defaultProducer = RequestObjectAwareOidcAuthorizeRequestProducer(
                discovery = properties,
                requestStrategy = requestStrategy,
                firstPassProducer = OidcAuthorizeRequestProducer(
                    lookup = clientLookup,
                    claimConverter = JacksonClaimConverter(objectMapper),
                    responseTypeValidator = OidcResponseTypeValidator
                )
            )
        )

    @Bean("accessRequestProducer")
    fun accessRequestProducer() = OAuthAccessRequestProducer(
        grantTypeValidator = OAuthGrantTypeValidator,
        clientAuthenticators = clientAuthenticators
    )
}