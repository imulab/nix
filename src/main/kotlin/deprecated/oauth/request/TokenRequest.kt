package deprecated.oauth.request

import deprecated.client.metadata.GrantType

interface TokenRequest : OidcRequest {

    override val grantTypes: Set<GrantType>
}