package deprecated.oauth.request

import deprecated.client.OAuthClient
import deprecated.client.metadata.GrantType
import deprecated.oauth.session.OAuthSession
import java.time.LocalDateTime
import java.util.*

class NixTokenRequest(
    override val id: String = UUID.randomUUID().toString(),
    override val requestTime: LocalDateTime = LocalDateTime.now(),
    override val client: OAuthClient,
    override val requestScopes: Set<String> = emptySet(),
    override val grantedScopes: MutableSet<String> = hashSetOf(),
    override val grantTypes: Set<GrantType> = hashSetOf(),
    override val session: OAuthSession,
    override val requestForm: Map<String, String> = emptyMap()
) : TokenRequest {

    override fun merge(another: OAuthRequest): OAuthRequest {
        check(another is TokenRequest) { "cannot merge OAuthRequest of different types." }
        return Builder().also { b ->
            b.id = id
            b.requestTime = requestTime
            b.client = client
            b.addGrantType(grantTypes)
            b.addGrantType(another.grantTypes)
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
            b.client = client
            b.addGrantType(grantTypes)
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
            var client: OAuthClient? = null,
            var requestScopes: MutableSet<String> = hashSetOf(),
            var grantedScopes: MutableSet<String> = hashSetOf(),
            var grantTypes: MutableSet<GrantType> = hashSetOf(),
            var session: OAuthSession? = null,
            var requestForm: MutableMap<String, String> = hashMapOf()
        ) {

            fun addGrantType(vararg gt: GrantType) = apply { grantTypes.addAll(gt) }

            fun addGrantType(gt: Collection<GrantType>) = apply { grantTypes.addAll(gt) }

            fun addRequestScope(vararg s: String) = apply { requestScopes.addAll(s) }

            fun addRequestScope(s: Collection<String>) = apply { requestScopes.addAll(s) }

            fun addGrantedScope(vararg s: String) = apply { grantedScopes.addAll(s) }

            fun addGrantedScope(s: Collection<String>) = apply { grantedScopes.addAll(s) }

            fun addRequestParameter(vararg p: Pair<String, String>) = apply { p.forEach { e -> requestForm[e.first] = e.second } }

            fun addRequestParameter(p: Collection<Pair<String, String>>) = apply { p.forEach { e -> requestForm[e.first] = e.second } }

            fun build(): TokenRequest {
                checkNotNull(client)
                checkNotNull(session)
                check(id.isNotBlank())

                return NixTokenRequest(
                    id = id,
                    requestTime = requestTime,
                    client = client!!,
                    requestScopes = requestScopes,
                    grantedScopes = grantedScopes,
                    grantTypes = grantTypes,
                    session = session!!,
                    requestForm = requestForm
                )
            }
        }
    }
}