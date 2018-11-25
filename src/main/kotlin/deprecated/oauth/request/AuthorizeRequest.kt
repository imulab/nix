package deprecated.oauth.request

import deprecated.client.metadata.ResponseType

interface AuthorizeRequest: OidcRequest {

    val responseTypes: Set<ResponseType>

    val redirectUri: String

    val state: String

    fun setHandled(responseType: ResponseType)

    fun hasHandledAll(): Boolean
}