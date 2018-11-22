package io.imulab.nix.oauth.validation

import io.imulab.nix.client.OidcClient
import io.imulab.nix.client.metadata.ClientType
import io.imulab.nix.constant.ErrorCode.Sub.INVALID_ID_TOKEN_CLAIM
import io.imulab.nix.constant.ErrorCode.Sub.INVALID_PROMPT
import io.imulab.nix.crypt.JwxProvider
import io.imulab.nix.error.InvalidRequestException
import io.imulab.nix.error.JwkException
import io.imulab.nix.oauth.request.AuthorizeRequest
import io.imulab.nix.oauth.request.OAuthRequest
import io.imulab.nix.oauth.request.Prompt
import io.imulab.nix.oauth.session.OidcSession
import io.imulab.nix.oauth.vor.ValueOrReference
import io.imulab.nix.support.assertType
import io.imulab.nix.support.getAuthTime
import io.imulab.nix.support.getRequestAtTime
import io.imulab.nix.support.plusSeconds
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwt.NumericDate

class OidcRequestValidator(
    private val allowedPrompts: List<Prompt> = listOf(
        Prompt.Login,
        Prompt.None,
        Prompt.Consent,
        Prompt.SelectAccount
    ),
    private val jwxProvider: JwxProvider,
    private val jwkValueOrReference: ValueOrReference<String, JsonWebKeySet, OidcClient>
) {

    suspend fun validateRequest(request: AuthorizeRequest) {
        assert(request.client is OidcClient)
        val client = request.client as OidcClient

        ValidOidcRequest(request).also {
            // prompts
            it.mustOnlyAllowedPrompts(allowedPrompts)
            it.mustStandaloneNonePrompt()
            it.mustNotNonePromptIfPublicClient()
            when {
                it.prompts.contains(Prompt.None) -> {
                    it.mustAuthTime()
                    it.mustRequestTime()
                    it.mustAuthTimeIsBeforeRequestTime()
                }
                it.prompts.contains(Prompt.Login) -> {
                    if (it.authTime != null && it.reqTime != null)
                        it.mustAuthTimeIsAfterRequestTime()
                }
            }

            // claim
            it.mustNotEmptyClaimSubject()

            // auth_time
            it.optionalAuthTimeIsBeforeNow(authTimeLeeway)

            // max_age
            if (it.maxAge != null) {
                it.mustAuthTime()
                it.mustRequestTime()
                it.mustAuthTimePlusMaxAgeIsAfterRequestTime()
            }

            if (request.idTokenHint.isNotEmpty()) {
                val jwks = jwkValueOrReference.resolve(client.jsonWebKeySetValue, client.jsonWebKeySetUri, client)
                    ?: throw JwkException.Companion.JwksAcquireException()

                val jwt = jwxProvider.decodeIdJsonWebToken(
                    jwt = request.idTokenHint,
                    client = client,
                    jwks = jwks,
                    extraCriteria = { b ->
                        b.setSkipDefaultAudienceValidation()
                    })

                if (jwt.jwtClaims.subject != it.session.subject)
                    throw InvalidRequestException(
                        INVALID_ID_TOKEN_CLAIM,
                        "id token hint subject mismatched with session subject."
                    )
            }
        }
    }

    companion object {
        private const val authTimeLeeway: Long = 5

        class ValidOidcRequest(val request: OAuthRequest) {

            val session = request.session.assertType<OidcSession>()

            val prompts: Set<Prompt> = request.prompts

            val authTime: NumericDate? = session.idTokenClaims.getAuthTime()

            val reqTime: NumericDate? = session.idTokenClaims.getRequestAtTime()

            val maxAge: Long? = request.maxAge

            fun mustOnlyAllowedPrompts(allowed: List<Prompt>) {
                if (!allowed.containsAll(prompts))
                    throw InvalidRequestException(INVALID_PROMPT, "Some prompts were not allowed.")
            }

            fun mustStandaloneNonePrompt() {
                if (prompts.size > 1 && prompts.contains(Prompt.None))
                    throw InvalidRequestException(
                        INVALID_PROMPT,
                        "Prompt <${Prompt.None.specValue}> requested along with others."
                    )
            }

            fun mustNotNonePromptIfPublicClient() {
                if (request.client.type == ClientType.PUBLIC && prompts.contains(Prompt.None))
                    throw InvalidRequestException(
                        INVALID_PROMPT,
                        "Public client cannot use <${Prompt.None.specValue}> as prompt."
                    )
            }

            fun mustNotEmptyClaimSubject() {
                if (session.idTokenClaims.subject.isEmpty())
                    throw InvalidRequestException(INVALID_ID_TOKEN_CLAIM, "claim subject is empty.")
            }

            fun optionalAuthTimeIsBeforeNow(leewaySeconds: Long = 0) {
                if (authTime != null && authTime.isOnOrAfter(NumericDate.now().plusSeconds(leewaySeconds)))
                    throw InvalidRequestException(INVALID_ID_TOKEN_CLAIM, "auth_time is in the future.")
            }

            fun mustAuthTime() {
                if (authTime == null)
                    throw InvalidRequestException(INVALID_ID_TOKEN_CLAIM, "auth_time not specified.")
            }

            fun mustRequestTime() {
                if (reqTime == null)
                    throw InvalidRequestException(INVALID_ID_TOKEN_CLAIM, "rat not specified.")
            }

            fun mustAuthTimePlusMaxAgeIsAfterRequestTime() {
                if (authTime!!.plusSeconds(maxAge!!).isBefore(reqTime!!))
                    throw InvalidRequestException(INVALID_ID_TOKEN_CLAIM, "rat expired beyond auth_time and max_age.")
            }

            fun mustAuthTimeIsBeforeRequestTime() {
                if (authTime!!.isAfter(reqTime!!))
                    throw InvalidRequestException(INVALID_ID_TOKEN_CLAIM, "auth_time happened after rat.")
            }

            fun mustAuthTimeIsAfterRequestTime() {
                if (authTime!!.isBefore(reqTime!!))
                    throw InvalidRequestException(INVALID_ID_TOKEN_CLAIM, "auth_time happened after rat.")
            }
        }
    }
}