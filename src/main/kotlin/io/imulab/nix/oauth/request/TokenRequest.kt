package io.imulab.nix.oauth.request

import io.imulab.nix.client.metadata.GrantType

interface TokenRequest : OAuthRequest {

    val grantTypes: Set<GrantType>
}