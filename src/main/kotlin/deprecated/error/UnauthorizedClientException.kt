package deprecated.error

import deprecated.client.metadata.GrantType
import deprecated.constant.Error

/**
 * unauthorized_client
 *
 * The authenticated client is not authorized to use this authorization grant type.
 */
class UnauthorizedClientException(grantType: GrantType): OAuthException(
    code = Error.UNAUTHORIZED_CLIENT,
    subCode = Error.Sub.ILLEGAL_GRANT_TYPE,
    description = "The client is not authorized to use grant type ${grantType.specValue}."
) {
    override fun getStatus(): Int = 401
}