package io.imulab.nix.server.config

import io.imulab.nix.oauth.validation.*
import io.imulab.nix.oidc.validation.*
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class ValidationConfig @Autowired constructor(
    private val prop: NixProperties
) {

    @Bean
    fun stateValidator() = StateValidator(prop)

    @Bean
    fun nonceValidator() = NonceValidator(prop)

    @Bean
    fun supportValidator() = SupportValidator(prop)

    @Bean("authorizePreValidation")
    fun authorizationEndpointPreValidation(
        stateValidator: StateValidator,
        nonceValidator: NonceValidator,
        supportValidator: SupportValidator
    ) = OAuthRequestValidationChain(listOf(
        stateValidator,
        nonceValidator,
        ScopeValidator,
        RedirectUriValidator,
        OidcResponseTypeValidator,
        PromptValidator,
        MaxAgeValidator,
        DisplayValidator,
        supportValidator
    ))

    @Bean("authorizePostValidation")
    fun authorizationEndpointPostValidation() = OAuthRequestValidationChain(listOf(
        AuthTimeValidator
    ))
}