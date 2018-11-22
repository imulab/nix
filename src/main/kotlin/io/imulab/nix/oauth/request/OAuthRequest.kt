package io.imulab.nix.oauth.request

import io.imulab.nix.client.OAuthClient
import io.imulab.nix.client.metadata.GrantType
import io.imulab.nix.oauth.session.OAuthSession
import io.imulab.nix.support.*
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

    val nonce: String
        get() = requestForm.nonce()

    val prompts: Set<Prompt>
        get() = requestForm.prompts()

    val maxAge: Long?
        get() = requestForm.maxAgeOrNull()

    val idTokenHint: String
        get() = requestForm.idTokenHint()

    val acrValue: String
        get() = requestForm.acrValue()

    fun grantScope(scope: String) { grantedScopes.add(scope) }

    fun grantScopes(vararg scopes: String) { grantedScopes.addAll(scopes) }

    fun merge(another: OAuthRequest): OAuthRequest

    fun sanitize(safeParamKeys: List<String>): OAuthRequest
}