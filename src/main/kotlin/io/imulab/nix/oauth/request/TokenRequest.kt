package io.imulab.nix.oauth.request

import io.imulab.nix.client.metadata.GrantType

interface TokenRequest : OAuthRequest {

    override val grantTypes: Set<GrantType>
}