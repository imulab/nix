package io.imulab.nix.consent

import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.spi.http.HttpRequestReader

/**
 * Service interface for acquiring a consent from user.
 */
interface ConsentStrategy {

    fun acquireConsent(httpRequest: HttpRequestReader, authorizeRequest: AuthorizeRequest)
}