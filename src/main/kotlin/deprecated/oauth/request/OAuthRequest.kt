package deprecated.oauth.request

import deprecated.client.OAuthClient
import deprecated.client.metadata.GrantType
import deprecated.oauth.session.OAuthSession
import deprecated.support.grantTypes
import java.time.LocalDateTime

interface OAuthRequest {

    val id: String

    val requestTime: LocalDateTime

    val client: OAuthClient

    val requestScopes: Set<String>

    val grantedScopes: MutableSet<String>

    val session: OAuthSession

    val requestForm: Map<String, String>

    val grantTypes: Set<GrantType>
        get() = requestForm.grantTypes()

    fun grantScope(scope: String) { grantedScopes.add(scope) }

    fun grantScopes(vararg scopes: String) { grantedScopes.addAll(scopes) }

    fun merge(another: OAuthRequest): OAuthRequest

    fun sanitize(safeParamKeys: List<String>): OAuthRequest
}