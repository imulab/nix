package io.imulab.nix.oauth.request

import io.imulab.nix.client.OAuthClient
import io.imulab.nix.client.metadata.ResponseType
import io.imulab.nix.oauth.session.OAuthSession
import java.time.LocalDateTime
import java.util.*

class NixAuthorizeRequest(
    override val id: String = UUID.randomUUID().toString(),
    override val requestTime: LocalDateTime = LocalDateTime.now(),
    override val redirectUri: String = "",
    override val state: String = "",
    override val client: OAuthClient,
    override val responseTypes: Set<ResponseType> = emptySet(),
    override val requestScopes: Set<String> = emptySet(),
    override val grantedScopes: MutableSet<String> = hashSetOf(),
    override val session: OAuthSession,
    override val requestForm: Map<String, String> = emptyMap()
) : AuthorizeRequest {

    private val h = mutableSetOf<ResponseType>()

    override fun setHandled(responseType: ResponseType) { h.add(responseType) }

    override fun hasHandledAll(): Boolean = h.containsAll(responseTypes)

    override fun merge(another: OAuthRequest): OAuthRequest {
        check(another is AuthorizeRequest) { "cannot merge OAuthRequest of different types." }
        return Builder().also { b ->
            b.id = id
            b.requestTime = requestTime
            b.redirectUri = if (redirectUri.isNotBlank()) redirectUri else another.redirectUri
            b.state = state
            b.client = client
            b.addResponseType(responseTypes)
            b.addResponseType(another.responseTypes)
            b.addRequestScope(requestScopes)
            b.addRequestScope(another.requestScopes)
            b.addGrantedScope(grantedScopes)
            b.addGrantedScope(another.grantedScopes)
            b.session = session
            b.addRequestParameter(requestForm.toList())
            b.addRequestParameter(another.requestForm.toList())
        }.build()
    }

    override fun sanitize(safeParamKeys: List<String>): OAuthRequest {
        return Builder().also { b ->
            b.id = id
            b.requestTime = requestTime
            b.redirectUri = redirectUri
            b.state = state
            b.client = client
            b.addResponseType(responseTypes)
            b.addRequestScope(requestScopes)
            b.addGrantedScope(grantedScopes)
            b.session = session
            b.addRequestParameter(requestForm.toList().filter { safeParamKeys.contains(it.first) })
        }.build()
    }

    companion object {

        class Builder(
            var id: String = UUID.randomUUID().toString(),
            var requestTime: LocalDateTime = LocalDateTime.now(),
            var redirectUri: String? = null,
            var state: String? = null,
            var client: OAuthClient? = null,
            var responseTypes: MutableSet<ResponseType> = hashSetOf(),
            var requestScopes: MutableSet<String> = hashSetOf(),
            var grantedScopes: MutableSet<String> = hashSetOf(),
            var session: OAuthSession? = null,
            var requestForm: MutableMap<String, String> = hashMapOf()
        ) {

            fun addResponseType(vararg rt: ResponseType) = apply { responseTypes.addAll(rt) }

            fun addResponseType(rt: Collection<ResponseType>) = apply { responseTypes.addAll(rt) }

            fun addRequestScope(vararg s: String) = apply { requestScopes.addAll(s) }

            fun addRequestScope(s: Collection<String>) = apply { requestScopes.addAll(s) }

            fun addGrantedScope(vararg s: String) = apply { grantedScopes.addAll(s) }

            fun addGrantedScope(s: Collection<String>) = apply { grantedScopes.addAll(s) }

            fun addRequestParameter(vararg p: Pair<String, String>) = apply { p.forEach { e -> requestForm[e.first] = e.second } }

            fun addRequestParameter(p: Collection<Pair<String, String>>) = apply { p.forEach { e -> requestForm[e.first] = e.second } }

            fun build(): AuthorizeRequest {
                checkNotNull(client)
                checkNotNull(state)
                checkNotNull(session)
                check(responseTypes.isNotEmpty())
                check(id.isNotBlank())

                return NixAuthorizeRequest(
                    id = id,
                    requestTime = requestTime,
                    redirectUri = redirectUri ?: "",
                    state = state!!,
                    client = client!!,
                    responseTypes = responseTypes,
                    requestScopes = requestScopes,
                    grantedScopes = grantedScopes,
                    session = session!!,
                    requestForm = requestForm
                )
            }
        }
    }
}