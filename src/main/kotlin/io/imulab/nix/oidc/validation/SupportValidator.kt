package io.imulab.nix.oidc.validation

import io.imulab.nix.oauth.*
import io.imulab.nix.oauth.error.*
import io.imulab.nix.oauth.request.OAuthAccessRequest
import io.imulab.nix.oauth.request.OAuthRequest
import io.imulab.nix.oauth.validation.OAuthRequestValidation
import io.imulab.nix.oidc.discovery.Discovery
import io.imulab.nix.oidc.error.RequestNotSupported
import io.imulab.nix.oidc.request.OidcAuthorizeRequest
import io.imulab.nix.oidc.reserved.*

/**
 * Validates if the incoming parameters are actually supported by the server. Support information is supplied through
 * OIDC [Discovery] configuration.
 */
class SupportValidator(private val discovery: Discovery) : OAuthRequestValidation {
    override fun validate(request: OAuthRequest) {
        when (request) {
            is OidcAuthorizeRequest -> validate(request)
            is OAuthAccessRequest -> validate(request)
        }
    }

    private fun validate(request: OidcAuthorizeRequest) {
        request.responseTypes
            .find { !discovery.responseTypesSupported.contains(it) }
            .ifNotNullOrEmpty { throw UnsupportedResponseType.unsupported(it) }

        request.acrValues
            .find { !discovery.acrValuesSupported.contains(it) }
            .ifNotNullOrEmpty { throw RequestNotSupported.unsupported(OidcParam.acrValues) }

        request.claimsLocales
            .find { !discovery.claimsLocalesSupported.contains(it) }
            .ifNotNullOrEmpty { throw RequestNotSupported.unsupported(OidcParam.claimsLocales) }

        request.uiLocales
            .find { !discovery.uiLocalesSupported.contains(it) }
            .ifNotNullOrEmpty { throw RequestNotSupported.unsupported(OidcParam.uiLocales) }

        if (request.responseMode.isNotEmpty() && !discovery.responseModeSupported.contains(request.responseMode))
            throw RequestNotSupported.unsupported(OidcParam.responseMode)

        if (request.display.isNotEmpty() && !discovery.displayValuesSupported.contains(request.display))
            throw RequestNotSupported.unsupported(OidcParam.display)

        if (!request.claims.isEmpty() && !discovery.claimsParameterSupported)
            throw RequestNotSupported.unsupported(OidcParam.claims)
    }

    private fun validate(request: OAuthAccessRequest) {
        request.grantTypes.find { !discovery.grantTypesSupported.contains(it) }.let { unsupported ->
            if (unsupported != null)
                throw UnsupportedGrantType.unsupported(unsupported)
        }
    }
}
