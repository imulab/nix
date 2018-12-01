package io.imulab.nix.server.authz

import io.imulab.nix.oauth.*
import io.imulab.nix.oidc.*
import io.imulab.nix.oidc.discovery.OidcContext
import io.imulab.nix.server.authz.repo.OidcAuthorizeRequestRepository
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import java.time.Duration

/**
 * Strategy to process a login token relying necessary information from [OidcAuthorizeRequest] onto the
 * internal login provider. This strategy is responsible for generating a request token and decode the
 * response token.
 *
 * Note that right now, this strategy only supports signing the token. Encryption support may be provided
 * in the future.
 */
class LoginTokenStrategy(
    private val oidcContext: OidcContext,
    private val signingAlgorithm: JwtSigningAlgorithm = JwtSigningAlgorithm.RS256,
    private val tokenLifespan: Duration = Duration.ofMinutes(10),
    private val tokenAudience: String
) {

    fun generateLoginTokenRequest(request: OidcAuthorizeRequest): String {
        val jwk = oidcContext.masterJsonWebKeySet.mustKeyForSignature(signingAlgorithm)
        return JsonWebSignature().also { jws ->
            jws.payload = request.getClaims().toJson()
            jws.keyIdHeaderValue = jwk.keyId
            jws.key = jwk.resolvePrivateKey()
            jws.algorithmHeaderValue = JwtSigningAlgorithm.RS256.spec
        }.compactSerialization
    }

    fun decodeLoginTokenResponse(token: String): JwtClaims {
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
            c.subject = "login"

            if (maxAge > 0)
                c.setStringClaim(OidcParam.maxAge, maxAge.toString())
            if (display.isNotEmpty())
                c.setStringClaim(OidcParam.display, display)
            if (uiLocales.isNotEmpty())
                c.setStringClaim(OidcParam.uiLocales, uiLocales.joinToString(separator = space))
            if (loginHint.isNotEmpty())
                c.setStringClaim(OidcParam.loginHint, loginHint)
            if (acrValues.isNotEmpty())
                c.setStringClaim(OidcParam.acrValues, acrValues.joinToString(separator = space))
        }
    }
}

/**
 * An implementation of [OAuthRequestProducer] that handles re-entry requests that contain `login_token` parameter.
 * When `login_token` is present, parameter `auth_req_id` and `nonce` are also expected. These values will help
 * associate the `login_token` with an original authorize request, whose data will be updated using the content
 * of `login_token`.
 */
// TODO this should not try to expand the login_token, just use auth_req_id and nonce to revive original request.
// TODO call it ReviveAuthorizeRequestProducer. And put the login_token in session.
class LoginTokenAwareOidcRequestStrategy(
    private val oidcAuthorizeRequestRepository: OidcAuthorizeRequestRepository,
    private val loginTokenStrategy: LoginTokenStrategy
) : OAuthRequestProducer {

    override suspend fun produce(form: OAuthRequestForm): OAuthRequest {
        val f = form.assertType<OidcRequestForm>()

        require(form.loginToken.isNotEmpty()) {
            "This strategy should not be called if there is no login_token"
        }

        /*
        We don't delete the original request from repository. First, it should self expire automatically. Second, it
        may provide possibility to including login and consent attempts in one go in the future, if desired.
         */
        val originalRequest = oidcAuthorizeRequestRepository.get(f.authorizeRequestId, f.nonce)
            ?: throw AccessDenied.byServer("Cannot resume authentication session.")

        val loginTokenClaims = try {
            loginTokenStrategy.decodeLoginTokenResponse(f.loginToken)
        } catch (e: Exception) {
            throw AccessDenied.byServer("Invalid login token.")
        }

        return originalRequest.asBuilder().also { b ->
            b.session.originalRequestTime = originalRequest.requestTime
            b.session.subject = loginTokenClaims.subject            // TODO use subject obfuscator here
            b.session.acrValues.also {
                it.addAll(loginTokenClaims.acrValues())
                if (it.isEmpty())
                    it.add("0")
            }
            if (loginTokenClaims.hasClaim(IdTokenClaim.authTime))
                b.session.authTime = loginTokenClaims.getNumericDateClaimValue(IdTokenClaim.authTime).toLocalDateTime()
        }.build()
    }
}