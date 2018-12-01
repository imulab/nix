package io.imulab.nix.oidc.client.authn

import io.imulab.nix.oauth.OAuthContext
import io.imulab.nix.oauth.assertType
import io.imulab.nix.oauth.client.ClientLookup
import io.imulab.nix.oauth.client.OAuthClient
import io.imulab.nix.oauth.client.authn.ClientAuthenticator
import io.imulab.nix.oauth.error.InvalidClient
import io.imulab.nix.oauth.error.InvalidRequest
import io.imulab.nix.oauth.request.OAuthRequestForm
import io.imulab.nix.oidc.reserved.AuthenticationMethod
import io.imulab.nix.oidc.reserved.JwtSigningAlgorithm
import io.imulab.nix.oidc.request.OidcRequestForm
import io.imulab.nix.oidc.reserved.jwtBearerClientAssertionType
import org.jose4j.jwa.AlgorithmConstraints
import org.jose4j.jwt.consumer.InvalidJwtException
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.jose4j.keys.AesKey

/**
 * Implementation of [ClientAuthenticator] that supports [AuthenticationMethod.clientSecretJwt]. Note this authenticator
 * works under the **important assumption** that client secret is still plain text. If every client secret is actually
 * a hashed version of the actual secret, as in most secured implementations, the key verification process will most
 * definitely fail.
 *
 * In the future, a possible resolution to the aforementioned assumption could be skip key verification, but manually
 * extract the Json Web Signature object and obtain the signing key, which is assumed to be the plain text client
 * secret. Then comparing the plain text client secret with the hashed version stored using a password encoder.
 *
 * This authenticator enforces `client_assertion_type` to be the value of [jwtBearerClientAssertionType] and the
 * `client_assertion` to contain a valid JWT token, signed by client's secret key using one the HMAC-SHA2 series
 * algorithms (i.e. HS256, HS384, HS512). In addition, the JWT token satisfy the following:
 * - `jti` is set
 * - `exp` is set and haven't expired yet
 * - `iss` is set to client id.
 * - `sub` is set to client id.
 * - `aud` is set to the url of the authorization server token endpoint.
 *
 * If the above criteria is met and the JWT is verified, it considers the client as authenticated.
 */
class ClientSecretJwtAuthenticator(
    private val clientLookup: ClientLookup,
    private val oauthContext: OAuthContext
) : ClientAuthenticator {

    override fun supports(method: String): Boolean = method == AuthenticationMethod.clientSecretJwt

    override suspend fun authenticate(form: OAuthRequestForm): OAuthClient {
        val f = form.assertType<OidcRequestForm>()
        if (f.clientAssertionType != jwtBearerClientAssertionType)
            throw InvalidRequest.unmet("<client_assertion_type> must be $jwtBearerClientAssertionType to use ${AuthenticationMethod.clientSecretJwt}")

        val client = clientLookup.find(f.clientId)

        try {
            JwtConsumerBuilder().also { b ->
                b.setRequireJwtId()
                b.setRequireExpirationTime()
                b.setExpectedIssuer(client.id)
                b.setExpectedSubject(client.id)
                b.setExpectedAudience(oauthContext.tokenEndpointUrl)
                b.setJwsAlgorithmConstraints(
                    AlgorithmConstraints(
                        AlgorithmConstraints.ConstraintType.WHITELIST,
                        JwtSigningAlgorithm.HS256.algorithmIdentifier,
                        JwtSigningAlgorithm.HS384.algorithmIdentifier,
                        JwtSigningAlgorithm.HS512.algorithmIdentifier
                    )
                )
                b.setVerificationKey(AesKey(client.secret))
            }.build().process(f.clientAssertion)
        } catch (e: InvalidJwtException) {
            throw InvalidClient.authenticationFailed()
        }

        return client
    }
}