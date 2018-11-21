package io.imulab.nix.oauth.token.strategy

import io.imulab.nix.client.OidcClient
import io.imulab.nix.crypt.JwxProvider
import io.imulab.nix.oauth.request.OAuthRequest
import io.imulab.nix.oauth.session.OidcSession
import io.imulab.nix.oauth.token.JweToken
import io.imulab.nix.oauth.token.JwtToken
import io.imulab.nix.oauth.token.Token
import io.imulab.nix.oauth.token.TokenType
import io.imulab.nix.oauth.vor.ValueOrReference
import io.imulab.nix.support.assertType
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.Use
import org.jose4j.jwx.HeaderParameterNames

class JwxIdTokenStrategy(
    private val jwxProvider: JwxProvider,
    private val jwkValueOrReference: ValueOrReference<String, JsonWebKeySet, OidcClient>
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

        val jsonWebKeySet = jwkValueOrReference.resolve(
            client.jsonWebKeySetValue,
            client.jsonWebKeySetUri,
            client
        ) ?: TODO("cannot resolve jwks")
        val jsonWebKey = jsonWebKeySet.findJsonWebKey(
            null,
            client.idTokenSignedResponseAlgorithm.keyType,
            Use.SIGNATURE,
            client.idTokenSignedResponseAlgorithm.alg
        ) ?: TODO("cannot find jwk")

        val jsonWebToken = jwxProvider.generateJsonWebToken(
            claims = session.idTokenClaims,
            signingAlgorithm = client.idTokenSignedResponseAlgorithm,
            key = jsonWebKey.key,
            headers = mapOf(HeaderParameterNames.KEY_ID to jsonWebKey.keyId)
        )

        if (client.idTokenEncryptedResponseAlgorithm == null)
            return JwtToken(type = TokenType.IdToken, raw = jsonWebToken)

        return JweToken(type = TokenType.IdToken, raw = encryptIdTokenJwt(jsonWebToken, jsonWebKeySet, client))
    }

    private fun encryptIdTokenJwt(token: String, keySet: JsonWebKeySet, client: OidcClient): String {
        requireNotNull(client.idTokenEncryptedResponseAlgorithm)
        requireNotNull(client.idTokenEncryptedResponseEncoding)

        val jsonWebKey = keySet.findJsonWebKey(
            null,
            null,
            Use.ENCRYPTION,
            client.idTokenEncryptedResponseAlgorithm!!.identifier
        ) ?: TODO("cannot find jwk")
        return jwxProvider.generateJsonWebEncryption(
            payload = token,
            key = jsonWebKey.key,
            keyAlg = client.idTokenEncryptedResponseAlgorithm!!,
            encAlg = client.idTokenEncryptedResponseEncoding!!
        )
    }
}