package io.imulab.nix.oidc.client.authn

import io.imulab.nix.oauth.OAuthContext
import io.imulab.nix.oauth.assertType
import io.imulab.nix.oauth.client.ClientLookup
import io.imulab.nix.oauth.client.OAuthClient
import io.imulab.nix.oauth.client.authn.ClientAuthenticator
import io.imulab.nix.oauth.error.InvalidClient
import io.imulab.nix.oauth.error.InvalidRequest
import io.imulab.nix.oauth.request.OAuthRequestForm
import io.imulab.nix.oidc.client.OidcClient
import io.imulab.nix.oidc.jwk.JsonWebKeySetStrategy
import io.imulab.nix.oidc.jwk.mustKeyWithId
import io.imulab.nix.oidc.jwk.resolvePublicKey
import io.imulab.nix.oidc.request.OidcRequestForm
import io.imulab.nix.oidc.reserved.AuthenticationMethod
import io.imulab.nix.oidc.reserved.JwtSigningAlgorithm
import io.imulab.nix.oidc.reserved.jwtBearerClientAssertionType
import org.jose4j.jwa.AlgorithmConstraints
import org.jose4j.jwk.Use
import org.jose4j.jwt.consumer.InvalidJwtException
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.jose4j.keys.AesKey

/**
 * Implementation of [ClientAuthenticator] that supports [AuthenticationMethod.privateKeyJwt].
 *
 * This authenticator enforces `client_assertion_type` to be the value of [jwtBearerClientAssertionType] and the
 * `client_assertion` to contain a valid JWT token, signed by client's private key whose public key is registered
 * with the authorization server. In addition, the JWT token satisfy the following:
 * - `jti` is set
 * - `exp` is set and haven't expired yet
 * - `iss` is set to client id.
 * - `sub` is set to client id.
 * - `aud` is set to the url of the authorization server token endpoint.
 *
 * During key resolution, the server will use client secret as verification key if JWT uses a HMAC-SHA2 based algorithm.
 * Otherwise, the server tries to look for a `kid` value in the JWT header first. It is suggested that
 * client set this header as a courtesy as it greatly simplifies the key resolution process. However, when `kid` is
 * not set, server tries to find a key within the client's registered json web key set whose algorithm matches the
 * `alg` JWT header, and is indeed purpose for signature (`use = signature`). If none of these methods yields a
 * verification key, the authentication process is considered failed.
 *
 * If the above criteria is met and the JWT is verified, it considers the client as authenticated.
 */
class PrivateKeyJwtAuthenticator(
    private val clientLookup: ClientLookup,
    private val clientJwksStrategy: JsonWebKeySetStrategy,
    private val oauthContext: OAuthContext
) : ClientAuthenticator {

    override fun supports(method: String): Boolean = method == AuthenticationMethod.privateKeyJwt

    override suspend fun authenticate(form: OAuthRequestForm): OAuthClient {
        val f = form.assertType<OidcRequestForm>()
        if (f.clientAssertionType != jwtBearerClientAssertionType)
            throw InvalidRequest.unmet("<client_assertion_type> must be $jwtBearerClientAssertionType to use ${AuthenticationMethod.privateKeyJwt}")

        val client = clientLookup.find(f.clientId).assertType<OidcClient>()
        val jwks = clientJwksStrategy.resolveKeySet(client)

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
                        JwtSigningAlgorithm.HS512.algorithmIdentifier,
                        JwtSigningAlgorithm.RS256.algorithmIdentifier,
                        JwtSigningAlgorithm.RS384.algorithmIdentifier,
                        JwtSigningAlgorithm.RS512.algorithmIdentifier,
                        JwtSigningAlgorithm.PS256.algorithmIdentifier,
                        JwtSigningAlgorithm.PS384.algorithmIdentifier,
                        JwtSigningAlgorithm.PS512.algorithmIdentifier
                    )
                )
                b.setVerificationKeyResolver { jws, _ ->
                    requireNotNull(jws) { "Json web signature must exist." }

                    return@setVerificationKeyResolver when (jws.algorithmHeaderValue) {
                        JwtSigningAlgorithm.HS256.algorithmIdentifier,
                        JwtSigningAlgorithm.HS384.algorithmIdentifier,
                        JwtSigningAlgorithm.HS512.algorithmIdentifier -> AesKey(
                            client.secret
                        )
                        else -> {
                            when {
                                jws.keyIdHeaderValue != null ->
                                    jwks.mustKeyWithId(jws.keyIdHeaderValue).resolvePublicKey()
                                jws.algorithmHeaderValue != null ->
                                    jwks.findJsonWebKey(null, null, Use.SIGNATURE, jws.algorithmHeaderValue)
                                        ?.resolvePublicKey()
                                else -> throw InvalidClient.authenticationFailedWithReason("verification key resolution failure")
                            }
                        }
                    }
                }
            }.build().process(f.clientAssertion)
        } catch (e: InvalidJwtException) {
            throw InvalidClient.authenticationFailed()
        }

        return client
    }
}