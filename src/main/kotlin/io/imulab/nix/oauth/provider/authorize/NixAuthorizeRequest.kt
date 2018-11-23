package io.imulab.nix.oauth.provider.authorize

import io.imulab.astrea.domain.extension.containsNone
import io.imulab.nix.client.OAuthClient
import io.imulab.nix.client.OidcClient
import io.imulab.nix.constant.Error
import io.imulab.nix.constant.Param
import io.imulab.nix.constant.Scope
import io.imulab.nix.crypt.alg.SigningAlgorithm
import io.imulab.nix.crypt.sign.OidcRequestObjectVerificationKeyResolver
import io.imulab.nix.oauth.request.AuthorizeRequest
import io.imulab.nix.oauth.request.NixAuthorizeRequest.Companion.Builder
import io.imulab.nix.oauth.session.Session
import io.imulab.nix.support.*
import io.ktor.application.ApplicationCall
import kotlinx.coroutines.*
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.jose4j.jwt.consumer.JwtContext

internal suspend fun NixAuthorizeProvider.doHandleAuthorizeRequest(call: ApplicationCall): AuthorizeRequest {
    val builder = Builder().also { b ->
        b.requestForm = call.parseRequestForm().toMutableMap()
    }

    val deferredClient = requestScope.async(Dispatchers.IO) {
        clientStore.getClient(builder.requestForm.mustClientId())
    }

    return builder.also { b ->
        populateOidcRequestObject(b, deferredClient)
        expandOidcRequestObject(b, deferredClient.await() as OidcClient)
        populateParameters(b, deferredClient.await())
        expandIdTokenHint(b, deferredClient.await() as OidcClient)
    }.build()
}

private fun NixAuthorizeProvider.populateParameters(builder: Builder, c: OAuthClient) {
    with(builder) {
        requireNotNull(requestForm)
        client = c
        redirectUri = requestForm.redirectUri().let { formUri ->
            if (formUri.isBlank()) {
                when (c.redirectUris.size) {
                    1 -> c.redirectUris[0].asValid()
                    0 -> throw Error.RedirectUri.noneRegistered()
                    else -> throw Error.RedirectUri.multipleRegistered()
                }
            } else {
                if (c.redirectUris.contains(redirectUri))
                    formUri.asValid()
                else
                    throw Error.RedirectUri.rouge()
            }
        }
        state = requestForm.state().also { s ->
            if (s.isEmpty())
                throw Error.State.missing()
            if (s.length < stateEntropy)
                throw Error.State.entropy()
        }
        addResponseType(requestForm.responseTypes())
        addRequestScope(requestForm.scopes())
        session = Session()
    }
}

private suspend fun NixAuthorizeProvider.populateOidcRequestObject(builder: Builder, client: Deferred<OAuthClient>) {
    with(builder) {
        if (requestForm.scopes().containsNone(Scope.OPENID))
            return
        oidcRequestObjectVor.resolve(requestForm.request(), requestForm.requestUri(), client)
            ?.let { requestForm[Param.REQUEST] = it }
    }
}

private suspend fun NixAuthorizeProvider.expandOidcRequestObject(builder: Builder, client: OidcClient) = with(builder) {
    if (!requestForm.containsKey(Param.REQUEST))
        return

    /**
     * Step One
     * --------
     * If client asserts that its request object is an encrypted JWT (by configuring
     * request_object_encryption_alg and request_object_encryption_enc), we need to decrypt
     * it first using the server's private key.
     *
     * If client asserts that its request object is an unencrypted JWT (by leaving
     * request_object_encryption_alg blank), then we pass on the request object as to next stage.
     */

    val requestObject: String = if (client.requestObjectEncryptionAlgorithm == null) {
        requestForm[Param.REQUEST]!!
    } else {
        requireNotNull(client.requestObjectEncryptionEncoding) {
            "when request_object_encryption_alg is set, request_object_encryption_enc must be set."
        }
        serverJsonWebKeySet.findKeyForJweKeyManagement(client.requestObjectEncryptionAlgorithm!!)
            .let { jwk ->
                jwxProvider.decryptJsonWebEncryption(
                    encrypted = requestForm[Param.REQUEST]!!,
                    encAlg = client.requestObjectEncryptionEncoding!!,
                    keyAlg = client.requestObjectEncryptionAlgorithm!!,
                    key = jwk.resolvePrivateKey()
                )
            }
    }

    /**
     * Step Two
     * --------
     * The JWT needs to be verified. According to OIDC spec: "The Request Object MAY be signed or unsigned (plaintext)".
     *
     * When it is plaintext, this is indicated by use of the none algorithm in the JOSE Header.
     *
     * If signed, the Request Object SHOULD contain the Claims iss (issuer) and aud (audience) as members.
     * The iss value SHOULD be the Client ID of the RP, unless it was signed by a different party than the RP.
     * The aud value SHOULD be or include the OP's Issuer Identifier URL.
     */
    val jwtContext: JwtContext = when (client.requestObjectSigningAlgorithm) {
        SigningAlgorithm.None -> {
            JwtConsumerBuilder()
                .setRequireJwtId()
                .setSkipVerificationKeyResolutionOnNone()
                .build()
                .process(requestObject)
        }
        else -> {
            val clientJwks = jsonWebKeySetVor.resolve(client.jsonWebKeySetValue, client.jsonWebKeySetUri, client)
                ?: throw Error.Jwks.noJwks()
            val keyResolver = OidcRequestObjectVerificationKeyResolver(clientJwks, client.requestObjectSigningAlgorithm)

            JwtConsumerBuilder()
                .setRequireJwtId()
                .setVerificationKeyResolver(keyResolver)
                .setExpectedIssuers(true, null)     // any value is acceptable
                .setExpectedAudience(oidcRequestObjectAudience)
                .build()
                .process(requestObject)
        }
    }

    /**
     * Step Three
     * ----------
     * Merge the claimed fields back into the request as parameters. Claims from the request object is considered fixed,
     * hence any parameters supplied from url queries takes precedence.
     *
     * If a parameter is supplied from both url queries and in request object. When the parameter type is simple
     * string (for instance, the state parameter), request object parameter will be ignored. When the parameter type
     * can be effectively merged (for instance, the scope parameter which is a space delimited list), the request object
     * parameter will be merged back into the url query parameters.
     *
     * Any parameter which is present in the request object but not from the url queries are retained.
     */
    jwtContext.jwtClaims.let { c ->
        requestForm.run {
            listOf(
                Param.REDIRECT_URI,
                Param.STATE,
                Param.NONCE,
                Param.RESPONSE_MODE,                    // TODO not used or validated
                Param.DISPLAY,                          // TODO not used or validated
                Param.MAX_AGE,
                Param.UI_LOCALES,                       // TODO not used or validated
                Param.CLAIMS_LOCALES,                   // TODO not used or validated
                Param.ID_TOKEN_HINT,
                Param.LOGIN_HINT,                        // TODO not used or validated
                Param.CLAIMS                             // TODO not used or validated
            ).forEach { p -> switchIfEmpty(p, c.maybe(p)) }

            listOf(
                Param.RESPONSE_TYPE,
                Param.SCOPE,
                Param.PROMPT,
                Param.ACR_VALUES                        // TODO not used or validated
            ).forEach { p -> merge(p, c.maybe(p)) }
        }
    }
}

private suspend fun NixAuthorizeProvider.expandIdTokenHint(builder: Builder, client: OidcClient) {

}