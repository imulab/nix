package io.imulab.nix.error

import io.imulab.nix.client.metadata.GrantType
import io.imulab.nix.constant.ErrorCode

/**
 * unauthorized_client
 *
 * The authenticated client is not authorized to use this authorization grant type.
 */
class UnauthorizedClientException(grantType: GrantType): OAuthException(
    code = ErrorCode.UNAUTHORIZED_CLIENT,
    subCode = ErrorCode.Sub.ILLEGAL_GRANT_TYPE,
    description = "The client is not authorized to use grant type ${grantType.specValue}."
) {
    override fun getStatus(): Int = 401
}