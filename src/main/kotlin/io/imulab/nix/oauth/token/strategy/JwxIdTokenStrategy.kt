package io.imulab.nix.oauth.token.strategy

import io.imulab.nix.client.OidcClient
import io.imulab.nix.client.metadata.GrantType
import io.imulab.nix.constant.ErrorCode
import io.imulab.nix.constant.ErrorCode.Sub.JWKS_ACQUIRE_FAILURE
import io.imulab.nix.constant.ErrorCode.Sub.JWK_SEEK_FAILURE
import io.imulab.nix.crypt.JwxProvider
import io.imulab.nix.error.InvalidRequestException
import io.imulab.nix.error.JwkException
import io.imulab.nix.oauth.request.OAuthRequest
import io.imulab.nix.oauth.request.Prompt
import io.imulab.nix.oauth.session.OidcSession
import io.imulab.nix.oauth.token.JweToken
import io.imulab.nix.oauth.token.JwtToken
import io.imulab.nix.oauth.token.Token
import io.imulab.nix.oauth.token.TokenType
import io.imulab.nix.oauth.validation.OidcRequestValidation
import io.imulab.nix.oauth.validation.OidcRequestValidation.Companion.mustAuthTime
import io.imulab.nix.oauth.validation.OidcRequestValidation.Companion.mustAuthTimeIsAfterRequestTime
import io.imulab.nix.oauth.validation.OidcRequestValidation.Companion.mustAuthTimeIsBeforeRequestTime
import io.imulab.nix.oauth.validation.OidcRequestValidation.Companion.mustAuthTimePlusMaxAgeIsAfterRequestTime
import io.imulab.nix.oauth.validation.OidcRequestValidation.Companion.mustRequestTime
import io.imulab.nix.oauth.validation.OidcRequestValidation.Companion.mustSinglePrompt
import io.imulab.nix.oauth.validation.OidcRequestValidation.Companion.onMaxAgeIsNotNull
import io.imulab.nix.oauth.validation.OidcRequestValidation.Companion.onPromptIsNotEmpty
import io.imulab.nix.oauth.validation.OidcRequestValidation.Companion.onThePromptIs
import io.imulab.nix.oauth.validation.OidcRequestValidation.Companion.optionalAuthTimeIsBeforeNow
import io.imulab.nix.oauth.vor.ValueOrReference
import io.imulab.nix.support.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.Use
import org.jose4j.jwt.NumericDate
import org.jose4j.jwx.HeaderParameterNames
import java.time.Duration
import java.time.temporal.ChronoUnit
import java.time.temporal.TemporalAmount

class JwxIdTokenStrategy(
    private val issuer: String,
    private val jwxProvider: JwxProvider,
    private val jwkValueOrReference: ValueOrReference<String, JsonWebKeySet, OidcClient>,
    private val jwkValueOrReferenceCoroutineScope: CoroutineScope,
    private val oidcRequestValidation: OidcRequestValidation,
    private val idTokenLifespan: TemporalAmount = Duration.ofHours(24)
) : IdTokenStrategy {

    override suspend fun generateIdToken(request: OAuthRequest): Token {
        val session = request.session.assertType<OidcSession>()

        require(session.idTokenClaims.subject.isNotEmpty()) {
            "oidc session id token subject claim is not set, did upstream overlook this?"
        }
        require(request.client is OidcClient) {
            "${javaClass.name} can only process requests from OidcClient."
        }

        val client = request.client as OidcClient

        val deferredJsonWebKeySet = jwkValueOrReferenceCoroutineScope.async {
            jwkValueOrReference.resolve(client.jsonWebKeySetValue, client.jsonWebKeySetUri, client)
                ?: throw JwkException(subCode = JWKS_ACQUIRE_FAILURE, message = "Failed to acquire Json Web Keys.")
        }

        if (!request.grantTypes.contains(GrantType.RefreshToken)) {
            oidcRequestValidation.load(request,
                optionalAuthTimeIsBeforeNow,
                onMaxAgeIsNotNull(
                    mustAuthTime,
                    mustRequestTime,
                    mustAuthTimePlusMaxAgeIsAfterRequestTime
                ),
                onPromptIsNotEmpty(
                    mustAuthTime,
                    mustSinglePrompt,
                    onThePromptIs(Prompt.None, mustAuthTime, mustRequestTime, mustAuthTimeIsBeforeRequestTime),
                    onThePromptIs(Prompt.Login, mustAuthTime, mustRequestTime, mustAuthTimeIsAfterRequestTime)
                )
            ).validate()

            if (request.acrValue.isNotEmpty() && session.idTokenClaims.getAcr().isEmpty())
                session.idTokenClaims.setAcr("0")

            if (request.idTokenHint.isNotEmpty()) {
                val hintJwt = jwxProvider.decodeIdJsonWebToken(
                    jwt = request.idTokenHint,
                    client = client,
                    jwks = deferredJsonWebKeySet.await(),
                    extraCriteria = { b ->
                        b.setSkipDefaultAudienceValidation()
                    })

                if (hintJwt.jwtClaims.subject != session.subject)
                    throw InvalidRequestException(
                        ErrorCode.Sub.INVALID_ID_TOKEN_CLAIM,
                        "id token hint subject mismatched with session subject."
                    )
            }
        }

        val jsonWebKey = deferredJsonWebKeySet.await().findJsonWebKey(null, client.idTokenSignedResponseAlgorithm.keyType,
            Use.SIGNATURE, client.idTokenSignedResponseAlgorithm.alg)
            ?: throw JwkException(subCode = JWK_SEEK_FAILURE, message = "Cannot locate any Json Web Key to sign id token.")

        val jsonWebToken = jwxProvider.generateJsonWebToken(
            claims = session.idTokenClaims.also {
                it.setExpirationTimeMinutesInTheFuture(idTokenLifespan.get(ChronoUnit.SECONDS).div(60).toFloat())
                it.setAuthTime(NumericDate.now())
                if (it.issuer.isNullOrEmpty())
                    it.issuer = issuer

                if (request.nonce.isNotEmpty())
                    it.setNonce(request.nonce)

                it.setAudience(*(it.audience.toHashSet().also { s -> s.add(client.id) }.toTypedArray()))

                it.issuedAt = NumericDate.now()
            },
            headers = HashMap<String, String>(session.idTokenHeaders).also {
                it[HeaderParameterNames.KEY_ID] = jsonWebKey.keyId
            },
            signingAlgorithm = client.idTokenSignedResponseAlgorithm,
            key = jsonWebKey.key
        )

        if (client.idTokenEncryptedResponseAlgorithm == null)
            return JwtToken(type = TokenType.IdToken, raw = jsonWebToken)

        return JweToken(type = TokenType.IdToken, raw = encryptIdTokenJwt(jsonWebToken, deferredJsonWebKeySet.await(), client))
    }

    private fun encryptIdTokenJwt(token: String, keySet: JsonWebKeySet, client: OidcClient): String {
        requireNotNull(client.idTokenEncryptedResponseAlgorithm)
        requireNotNull(client.idTokenEncryptedResponseEncoding)

        val jsonWebKey = keySet.findJsonWebKey(null, null, Use.ENCRYPTION, client.idTokenEncryptedResponseAlgorithm!!.identifier)
            ?: throw JwkException(subCode = JWK_SEEK_FAILURE, message = "Cannot locate any Json Web Key to encrypt id token.")

        return jwxProvider.generateJsonWebEncryption(
            payload = token,
            key = jsonWebKey.key,
            keyAlg = client.idTokenEncryptedResponseAlgorithm!!,
            encAlg = client.idTokenEncryptedResponseEncoding!!
        )
    }
}