package io.imulab.nix.oauth.validation

import io.imulab.astrea.domain.PARAM_ID_TOKEN
import io.imulab.astrea.error.RequestParameterInvalidValueException
import io.imulab.nix.constant.ErrorCode
import io.imulab.nix.error.InvalidRequestException
import io.imulab.nix.oauth.request.OAuthRequest
import io.imulab.nix.oauth.request.Prompt
import io.imulab.nix.oauth.session.OidcSession
import io.imulab.nix.support.assertType
import io.imulab.nix.support.getAuthTime
import io.imulab.nix.support.getRequestAtTime
import io.imulab.nix.support.plusSeconds
import org.jose4j.jwt.NumericDate

class OidcRequestValidation(
    private val allowedPrompts: List<Prompt> = listOf(
        Prompt.Login,
        Prompt.None,
        Prompt.Consent,
        Prompt.SelectAccount
    )
) {

    companion object {
        val mustOnlyAllowedPrompts: OidcRequestValidationRule = { v ->
            if (!v.allowedPrompts.containsAll(v.prompts))
                throw InvalidRequestException(ErrorCode.Sub.INVALID_PROMPT, "Some prompts were not allowed.")
        }

        val mustStandaloneNonePrompt: OidcRequestValidationRule = { v ->
            if (v.prompts.size > 1 && v.prompts.contains(Prompt.None))
                throw InvalidRequestException(ErrorCode.Sub.INVALID_PROMPT, "Prompt <${Prompt.None.specValue}> requested along with others.")
        }

        val optionalAuthTimeIsBeforeNow: OidcRequestValidationRule = { v ->
            if (v.authTime != null && v.authTime.isOnOrAfter(NumericDate.now().plusSeconds(v.clockLeeway)))
                throw InvalidRequestException(ErrorCode.Sub.INVALID_ID_TOKEN_CLAIM, "auth_time is in the future.")
        }

        val mustAuthTime: OidcRequestValidationRule = { v ->
            if (v.authTime == null)
                throw InvalidRequestException(ErrorCode.Sub.INVALID_ID_TOKEN_CLAIM, "auth_time not specified.")
        }

        val mustRequestTime: OidcRequestValidationRule = { v ->
            if (v.reqTime == null)
                throw InvalidRequestException(ErrorCode.Sub.INVALID_ID_TOKEN_CLAIM, "rat not specified.")
        }

        val mustAuthTimePlusMaxAgeIsAfterRequestTime: OidcRequestValidationRule = { v ->
            if (v.authTime!!.plusSeconds(v.maxAge!!).isBefore(v.reqTime!!))
                throw InvalidRequestException(ErrorCode.Sub.INVALID_ID_TOKEN_CLAIM, "rat expired beyond auth_time and max_age.")
        }

        val mustSinglePrompt: OidcRequestValidationRule = { v ->
            if (v.prompts.size > 1)
                throw InvalidRequestException(ErrorCode.Sub.INVALID_PROMPT, "more than one prompt.")
        }

        val mustAuthTimeIsBeforeRequestTime: OidcRequestValidationRule = { v ->
            if (v.authTime!!.isAfter(v.reqTime!!))
                throw RequestParameterInvalidValueException(PARAM_ID_TOKEN, "auth_time happened after rat.")
        }

        val mustAuthTimeIsAfterRequestTime: OidcRequestValidationRule = { v ->
            if (v.authTime!!.isBefore(v.reqTime!!))
                throw RequestParameterInvalidValueException(PARAM_ID_TOKEN, "auth_time happened after rat.")
        }

        fun onMaxAgeIsNotNull(vararg rules: OidcRequestValidationRule): OidcRequestValidationRule = { v ->
            if (v.maxAge != null) {
                rules.forEach { it(v) }
            }
        }

        fun onPromptIsNotEmpty(vararg rules: OidcRequestValidationRule): OidcRequestValidationRule = { v ->
            if (v.prompts.isNotEmpty()) {
                rules.forEach { it(v) }
            }
        }

        fun onThePromptIs(expected: Prompt, vararg rules: OidcRequestValidationRule): OidcRequestValidationRule = { v ->
            assert(v.prompts.size == 1)
            if (v.prompts.first() == expected)
                rules.forEach { it(v) }
        }
    }

    fun load(request: OAuthRequest, vararg rules: OidcRequestValidationRule): ValidationSession =
            ValidationSession(request).also { it.rules.addAll(rules) }
}

class ValidationSession(val request: OAuthRequest,
                        val clockLeeway: Long = 5,
                        val allowedPrompts: List<Prompt> = listOf(
                            Prompt.Login,
                            Prompt.None,
                            Prompt.Consent,
                            Prompt.SelectAccount
                        )) {

    val session = request.session.assertType<OidcSession>()

    val prompts: Set<Prompt> = request.prompts

    val authTime: NumericDate? = session.idTokenClaims.getAuthTime()

    val reqTime: NumericDate? = session.idTokenClaims.getRequestAtTime()

    val maxAge: Long? = request.maxAge

    var rules: MutableList<OidcRequestValidationRule> = mutableListOf()

    fun validate() { rules.forEach { it(this) } }
}

typealias OidcRequestValidationRule = (ValidationSession) -> Unit