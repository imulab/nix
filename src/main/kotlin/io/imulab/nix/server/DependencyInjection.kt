package io.imulab.nix.server

import io.imulab.nix.oauth.*
import io.imulab.nix.oidc.*
import io.imulab.nix.oidc.discovery.OidcContext
import io.imulab.nix.server.authz.ResumeOidcAuthorizeRequestProducer
import io.imulab.nix.server.route.AuthorizeRouteProvider
import org.kodein.di.Kodein
import org.kodein.di.erased.bind
import org.kodein.di.erased.instance
import org.kodein.di.erased.singleton

/**
 * Declare dependency injection modules.
 */
object DependencyInjection {

    val configuration = Kodein.Module(name = "configuration") {
        bind<OidcContext>() with singleton {
            ServerContext(config = instance(), jsonWebKeySetRepository = instance())
        }
    }

    val requestProducers = Kodein.Module(name = "requestProducers") {
        bind<OAuthRequestProducer>() with singleton {
            ResumeOidcAuthorizeRequestProducer(
                oidcAuthorizeRequestRepository = instance("TODO"),
                defaultProducer = RequestObjectAwareOidcAuthorizeRequestProducer(
                    discovery = instance("TODO"),
                    requestStrategy = instance("TODO"),
                    claimsJsonConverter = instance("TODO"),
                    firstPassProducer = OidcAuthorizeRequestProducer(
                        lookup = instance("TODO"),
                        claimsJsonConverter = instance("TODO"),
                        responseTypeValidator = OidcResponseTypeValidator
                    )
                )
            )
        }
    }

    val validators = Kodein.Module(name = "validators") {
        bind() from singleton { StateValidator(oauthContext = instance()) }
        bind() from singleton { NonceValidator(oidcContext = instance()) }
    }

    val routeProviders = Kodein.Module(name = "routeProviders") {
        bind() from singleton {
            AuthorizeRouteProvider(
                requestProducer = instance("TODO"),
                preValidation = instance("TODO"),
                postValidation = instance("TODO")
            )
        }
    }
}