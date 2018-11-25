package deprecated.oauth

import io.imulab.astrea.client.ClientManager
import io.imulab.astrea.client.DefaultOAuthClient
import io.imulab.astrea.client.DefaultOidcClient
import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.crypt.BCryptPasswordEncoder
import io.imulab.astrea.crypt.SigningAlgorithm
import io.imulab.astrea.domain.*
import io.imulab.astrea.error.InvalidClientException
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use

/**
 * A dummy [ClientManager] used for development only. This client manager only returns an oauth client named
 * foo or an open id connect client named bar. All other client id requests are returned with client not found
 * error.
 */
class FooBarClientManager: ClientManager {

    private val passwordEncoder = BCryptPasswordEncoder()

    override fun getClient(id: String): OAuthClient {
        return when (id) {
            "foo" -> {
                DefaultOAuthClient(
                    id = id,
                    secret = "s3cret".let {
                        passwordEncoder.encode(it).toByteArray()
                    },
                    responseTypes = listOf(
                        ResponseType.Code,
                        ResponseType.Token
                    ),
                    grantTypes = listOf(
                        GrantType.AuthorizationCode,
                        GrantType.Implicit,
                        GrantType.ClientCredentials,
                        GrantType.RefreshToken
                    ),
                    scopes = listOf(
                        SCOPE_OFFLINE,
                        "foo",
                        "bar",
                        "foobar"
                    ),
                    redirectUris = listOf(
                        "http://localhost:8888/callback",
                        "http://localhost:8888/callback2"),
                    public = false
                )
            }
            "bar" -> {
                DefaultOidcClient(
                    oauth = DefaultOAuthClient(
                        id = id,
                        secret = "s3cret".let {
                            passwordEncoder.encode(it).toByteArray()
                        },
                        responseTypes = listOf(
                            ResponseType.Code,
                            ResponseType.Token,
                            ResponseType.IdToken
                        ),
                        grantTypes = listOf(
                            GrantType.AuthorizationCode,
                            GrantType.Implicit,
                            GrantType.ClientCredentials,
                            GrantType.RefreshToken
                        ),
                        scopes = listOf(
                            SCOPE_OPENID,
                            SCOPE_OFFLINE,
                            "foo",
                            "bar",
                            "profile"
                        ),
                        redirectUris = listOf(
                            "http://localhost:8888/callback",
                            "http://localhost:8888/callback2"
                        ),
                        public = false
                    ),
                    jwk = JsonWebKeySet().also {
                        it.addJsonWebKey(RsaJwkGenerator.generateJwk(2048).also { jwk ->
                            jwk.keyId = "bar_jwk"
                            jwk.use = Use.SIGNATURE
                        })
                    },
                    requestUris = listOf("http://localhost:8888/"),
                    tokenEndpointAuth = AuthMethod.ClientSecretPost,
                    reqObjSignAlg = SigningAlgorithm.RS256
                )
            }
            else -> throw InvalidClientException.NotFound()
        }
    }
}