package io.imulab.nix.server.config

import io.imulab.nix.oauth.request.OAuthRequestProducer
import io.imulab.nix.oauth.validation.StateValidator
import io.imulab.nix.oidc.client.MemoryClientStorage
import io.imulab.nix.oidc.discovery.OidcContext
import io.imulab.nix.oidc.jwk.JsonWebKeySetRepository
import io.imulab.nix.oidc.jwk.JsonWebKeySetStrategy
import io.imulab.nix.oidc.jwk.MemoryJsonWebKeySetRepository
import io.imulab.nix.oidc.request.*
import io.imulab.nix.oidc.reserved.JweKeyManagementAlgorithm
import io.imulab.nix.oidc.reserved.JwtSigningAlgorithm
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
import io.ktor.client.HttpClient
import io.ktor.client.engine.apache.Apache
import io.ktor.config.ApplicationConfig
import io.ktor.util.KtorExperimentalAPI
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import org.kodein.di.Kodein
import org.kodein.di.erased.bind
import org.kodein.di.erased.instance
import org.kodein.di.erased.singleton

/**
 * Declare dependency injection modules.
 */
@UseExperimental(KtorExperimentalAPI::class)
class DependencyInjection(private val config: ApplicationConfig) {

    private val defaultPersistence = Kodein.Module(name = "defaultPersistence") {
        bind<OidcAuthorizeRequestRepository>() with singleton { MemoryOidcAuthorizeRequestRepository() }
        bind<JsonWebKeySetRepository>() with singleton {
            MemoryJsonWebKeySetRepository(serverJwks = JsonWebKeySet().also { s ->
                s.addJsonWebKey(RsaJwkGenerator.generateJwk(2048).also { k ->
                    k.keyId = "c7b318fa-4fc0-4beb-baef-91285c7ba628"
                    k.use = Use.SIGNATURE
                    k.algorithm = JwtSigningAlgorithm.RS256.algorithmIdentifier
                })
                s.addJsonWebKey(RsaJwkGenerator.generateJwk(2048).also { k ->
                    k.keyId = "1eb56508-347b-4c8e-b040-5113aa18f26b"
                    k.use = Use.ENCRYPTION
                    k.algorithm = JweKeyManagementAlgorithm.RSA1_5.algorithmIdentifier
                })
            })
        }
        bind<CachedRequestRepository>() with singleton { MemoryRequestRepository() }
        bind<MemoryClientStorage>() with singleton { MemoryClientStorage() }    // should add some fake clients here.
    }

    private val shared = Kodein.Module(name = "shared") {
        importOnce(defaultPersistence, allowOverride = true)
        bind<JsonWebKeySetStrategy>() with singleton {
            JsonWebKeySetStrategy(
                jsonWebKeySetRepository = instance(),
                httpClient = HttpClient(Apache)
            )
        }
    }

    val configuration = Kodein.Module(name = "configuration") {
        importOnce(defaultPersistence, allowOverride = true)
        bind<ServerContext>() with singleton {
            ServerContext(config = config, jsonWebKeySetRepository = instance())
        }
    }

    private val requestProducers = Kodein.Module(name = "requestProducers") {
        importOnce(configuration)
        importOnce(defaultPersistence, allowOverride = true)
        importOnce(shared)
        bind<RequestStrategy>() with singleton {
            RequestStrategy(
                repository = instance(),
                serverContext = instance(),
                jsonWebKeySetStrategy = instance(),
                httpClient = HttpClient(Apache)
            )
        }
        bind<OAuthRequestProducer>(tag = "masterRequestProducer") with singleton {
            ResumeOidcAuthorizeRequestProducer(
                oidcAuthorizeRequestRepository = instance(),
                defaultProducer = RequestObjectAwareOidcAuthorizeRequestProducer(
                    discovery = instance(),
                    requestStrategy = instance(),
                    claimsJsonConverter = GsonClaimsConverter,
                    firstPassProducer = OidcAuthorizeRequestProducer(
                        lookup = instance(),
                        claimsJsonConverter = GsonClaimsConverter,
                        responseTypeValidator = OidcResponseTypeValidator
                    )
                )
            )
        }
    }

    private val authenticationProvider = Kodein.Module(name = "authenticationProvider") {
        importOnce(configuration)
        importOnce(defaultPersistence, allowOverride = true)
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
        importOnce(configuration)
        importOnce(defaultPersistence, allowOverride = true)
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
        // add validator chain here
    }

    val routeProviders = Kodein.Module(name = "routeProviders") {
        importOnce(requestProducers)
        importOnce(validators)
        importOnce(authenticationProvider)
        importOnce(consentProvider)
        bind() from singleton {
            AuthorizeRouteProvider(
                requestProducer = instance(tag = "masterRequestProducer"),
                preValidation = instance("TODO"),
                postValidation = instance("TODO"),
                authenticationProvider = instance(),
                consentProvider = instance()
            )
        }
    }
}