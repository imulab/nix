package io.imulab.nix.server.config

import io.imulab.nix.oauth.request.OAuthRequestProducer
import io.imulab.nix.oauth.validation.StateValidator
import io.imulab.nix.oidc.discovery.OidcContext
import io.imulab.nix.oidc.request.OidcAuthorizeRequestProducer
import io.imulab.nix.oidc.request.RequestObjectAwareOidcAuthorizeRequestProducer
import io.imulab.nix.oidc.validation.NonceValidator
import io.imulab.nix.oidc.validation.OidcResponseTypeValidator
import io.imulab.nix.server.authz.KtorSessionStrategy
import io.imulab.nix.server.authz.ResumeOidcAuthorizeRequestProducer
import io.imulab.nix.server.authz.authn.*
import io.imulab.nix.server.authz.authn.obfs.SubjectObfuscator
import io.imulab.nix.server.authz.consent.*
import io.imulab.nix.server.authz.repo.MemoryOidcAuthorizeRequestRepository
import io.imulab.nix.server.authz.repo.OidcAuthorizeRequestRepository
import io.imulab.nix.server.oidc.GsonClaimsConverter
import io.imulab.nix.server.route.AuthorizeRouteProvider
import io.imulab.nix.server.stringPropertyOrNull
import io.ktor.config.ApplicationConfig
import io.ktor.util.KtorExperimentalAPI
import org.kodein.di.Kodein
import org.kodein.di.erased.bind
import org.kodein.di.erased.instance
import org.kodein.di.erased.singleton

/**
 * Declare dependency injection modules.
 */
@UseExperimental(KtorExperimentalAPI::class)
class DependencyInjection(private val config: ApplicationConfig) {

    private val shared = Kodein.Module(name = "shared") {
        bind<OidcAuthorizeRequestRepository>() with singleton { MemoryOidcAuthorizeRequestRepository() }
    }

    val configuration = Kodein.Module(name = "configuration") {
        bind<OidcContext>() with singleton {
            ServerContext(config = config, jsonWebKeySetRepository = instance())
        }
    }

    private val requestProducers = Kodein.Module(name = "requestProducers") {
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

    private val authenticationProvider = Kodein.Module(name = "authenticationProvider") {
        import(shared)
        import(configuration)
        bind<SubjectObfuscator>() with singleton {
            SubjectObfuscator((config.stringPropertyOrNull("nix.security.subjectSalt") ?: "").toByteArray())
        }
        bind<LoginTokenStrategy>() with singleton { LoginTokenStrategy(serverContext = instance()) }
        bind<LoginTokenAuthenticationHandler>(tag = LoginTokenAuthenticationHandler::class) with singleton {
            LoginTokenAuthenticationHandler(
                loginTokenStrategy = instance(),
                sessionStrategy = KtorSessionStrategy
            )
        }
        bind<SessionAuthenticationHandler>(tag = SessionAuthenticationHandler::class) with singleton {
            SessionAuthenticationHandler(sessionStrategy = KtorSessionStrategy)
        }
        bind<AutoLoginAuthenticationHandler>(tag = AutoLoginAuthenticationHandler::class) with singleton {
            AutoLoginAuthenticationHandler()
        }
        bind<AuthenticationProvider>() with singleton {
            AuthenticationProvider(
                subjectObfuscator = instance(),
                serverContext = instance(),
                handlers = listOf(
                    instance(tag = LoginTokenAuthenticationHandler::class),
                    instance(tag = SessionAuthenticationHandler::class),
                    instance(tag = AutoLoginAuthenticationHandler::class)
                ),
                loginTokenStrategy = instance(),
                requestRepository = instance()
            )
        }
    }

    private val consentProvider = Kodein.Module(name = "consentProvider") {
        importOnce(shared)
        importOnce(configuration)
        bind<ConsentTokenStrategy>() with singleton {
            ConsentTokenStrategy(
                serverContext = instance(),
                claimsJsonConverter = GsonClaimsConverter
            )
        }
        bind<ConsentTokenConsentHandler>(tag = ConsentTokenConsentHandler::class) with singleton {
            ConsentTokenConsentHandler(
                consentTokenStrategy = instance(),
                sessionStrategy = KtorSessionStrategy
            )
        }
        bind<SessionConsentHandler>(tag = SessionConsentHandler::class) with singleton {
            SessionConsentHandler(sessionStrategy = KtorSessionStrategy)
        }
        bind<AutoGrantConsentHandler>(tag = AutoGrantConsentHandler::class) with singleton {
            AutoGrantConsentHandler()
        }
        bind<ConsentProvider>() with singleton {
            ConsentProvider(
                handlers = listOf(
                    instance(tag = ConsentTokenConsentHandler::class),
                    instance(tag = SessionConsentHandler::class),
                    instance(tag = AutoGrantConsentHandler::class)
                ),
                requestRepository = instance(),
                serverContext = instance(),
                consentTokenStrategy = instance(),
                requireAuthentication = true
            )
        }
    }

    private val validators = Kodein.Module(name = "validators") {
        bind() from singleton { StateValidator(oauthContext = instance()) }
        bind() from singleton { NonceValidator(oidcContext = instance()) }
    }

    val routeProviders = Kodein.Module(name = "routeProviders") {
        importOnce(shared)
        importOnce(requestProducers)
        importOnce(validators)
        importOnce(authenticationProvider)
        importOnce(consentProvider)
        bind() from singleton {
            AuthorizeRouteProvider(
                requestProducer = instance("TODO"),
                preValidation = instance("TODO"),
                postValidation = instance("TODO"),
                authenticationProvider = instance(),
                consentProvider = instance()
            )
        }
    }
}