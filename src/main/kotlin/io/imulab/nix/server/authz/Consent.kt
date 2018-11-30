package io.imulab.nix.server.authz

import io.imulab.nix.oauth.*
import io.imulab.nix.oidc.*
import io.imulab.nix.oidc.discovery.OidcContext
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import java.time.Duration

/**
 * Strategy to process a consent token relying necessary information from [OidcAuthorizeRequest] onto the
 * internal consent provider. This strategy is responsible for generating a request token and decode the
 * response token.
 *
 * Note that right now, this strategy only supports signing the token. Encryption support may be provided
 * in the future.
 */
class ConsentTokenStrategy(
    private val oidcContext: OidcContext,
    private val signingAlgorithm: JwtSigningAlgorithm = JwtSigningAlgorithm.RS256,
    private val tokenLifespan: Duration = Duration.ofMinutes(10),
    private val tokenAudience: String,
    private val claimsJsonConverter: ClaimsJsonConverter
) {

    fun generateConsentTokenRequest(request: OidcAuthorizeRequest): String {
        val jwk = oidcContext.masterJsonWebKeySet.mustKeyForSignature(signingAlgorithm)
        return JsonWebSignature().also { jws ->
            jws.payload = request.getClaims().toJson()
            jws.keyIdHeaderValue = jwk.keyId
            jws.key = jwk.resolvePrivateKey()
            jws.algorithmHeaderValue = JwtSigningAlgorithm.RS256.spec
        }.compactSerialization
    }

    fun decodeConsentTokenResponse(token: String): JwtClaims {
        return JwtConsumerBuilder()
            .setRequireJwtId()
            .setJwsAlgorithmConstraints(signingAlgorithm.whitelisted())
            .setVerificationKeyResolver(
                JwtVerificationKeyResolver(oidcContext.masterJsonWebKeySet, signingAlgorithm)
            )
            .setExpectedIssuer(tokenAudience)
            .setExpectedAudience(oidcContext.issuerUrl)
            .build()
            .processToClaims(token)
    }

    private fun OidcAuthorizeRequest.getClaims(): JwtClaims {
        return JwtClaims().also { c ->
            c.setGeneratedJwtId()
            c.setIssuedAtToNow()
            c.setNotBeforeMinutesInThePast(0f)
            c.setExpirationTimeMinutesInTheFuture(tokenLifespan.seconds.div(60).toFloat())
            c.issuer = oidcContext.issuer
            c.setAudience(tokenAudience, client.id)
            c.subject = session.subject

            if (display.isNotEmpty())
                c.setStringClaim(OidcParam.display, display)
            if (uiLocales.isNotEmpty())
                c.setStringClaim(OidcParam.uiLocales, uiLocales.joinToString(separator = space))
            if (scopes.isNotEmpty())
                c.setStringClaim(Param.scope, scopes.joinToString(separator = space))
            if (claimsLocales.isNotEmpty())
                c.setStringClaim(OidcParam.claimsLocales, scopes.joinToString(separator = space))

            // TODO right now, just include claim as a JSON string, this should be fixed later.
            c.setStringClaim(OidcParam.claims, claimsJsonConverter.toJson(claims))
        }
    }
}

/**
 * An implementation of [OAuthRequestProducer] that handles re-entry requests that contain `consent_token` parameter.
 * When `consent_token` is present, parameter `auth_req_id` and `nonce` are also expected. These values will help
 * associate the `login_token` with an original authorize request, whose data will be updated using the content
 * of `consent_token`.
 */
class ConsentTokenAwareOidcRequestStrategy(
    private val oidcAuthorizeRequestRepository: OidcAuthorizeRequestRepository,
    private val consentTokenStrategy: ConsentTokenStrategy
) : OAuthRequestProducer {
    override suspend fun produce(form: OAuthRequestForm): OAuthRequest {
        val f = form.assertType<OidcRequestForm>()

        require(form.consentToken.isNotEmpty()) {
            "This strategy should not be called if there is no consent_token"
        }

        /*
        We don't delete the original request from repository. First, it should self expire automatically. Second, it
        may provide possibility to including login and consent attempts in one go in the future, if desired.
         */
        val originalRequest = oidcAuthorizeRequestRepository.get(f.authorizeRequestId, f.nonce)
            ?: throw AccessDenied.byServer("Cannot resume authorization session.")

        val consentTokenClaims = try {
            consentTokenStrategy.decodeConsentTokenResponse(f.loginToken)
        } catch (e: Exception) {
            throw AccessDenied.byServer("Invalid consent token.")
        }

        if (originalRequest.session.subject != consentTokenClaims.subject)
            throw AccessDenied.byServer("Consent subject mismatch.")

        consentTokenClaims.scopes().forEach { originalRequest.grantScope(it) }
        // TODO claims should be placed into session, we ignore it here temporarily until we figure out what's the type

        return originalRequest
    }
}