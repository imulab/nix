package io.imulab.nix.oidc.validation

import io.imulab.nix.oauth.assertType
import io.imulab.nix.oauth.error.InvalidRequest
import io.imulab.nix.oauth.request.OAuthRequest
import io.imulab.nix.oauth.validation.OAuthRequestValidation
import io.imulab.nix.oauth.validation.SpecDefinitionValidator
import io.imulab.nix.oidc.request.OidcAuthorizeRequest
import io.imulab.nix.oidc.reserved.OidcParam
import io.imulab.nix.oidc.reserved.Prompt

/**
 * Validates the `prompt` parameter. The universe is `{none, login, consent, select_account}`. Because this parameter
 * is optional, empty set is allowed. However, `none` prompt must not be accompanied with other prompts.
 */
object PromptValidator : SpecDefinitionValidator,
    OAuthRequestValidation {
    override fun validate(request: OAuthRequest) {
        val prompts = request.assertType<OidcAuthorizeRequest>().prompts
        prompts.forEach { p -> validate(p) }
        if (prompts.contains(Prompt.none) && prompts.size > 1)
            throw InvalidRequest.unmet("prompt <none> must not appear along with other prompts")
    }

    override fun validate(value: String): String {
        return when(value) {
            Prompt.none, Prompt.login, Prompt.consent, Prompt.selectAccount -> value
            else -> throw InvalidRequest.invalid(OidcParam.prompt)
        }
    }
}