package io.imulab.nix.server.authz

//object ConsentTokenStrategySpec : Spek({
//
//    val strategy = ConsentTokenStrategy(
//        serverContext = BOM.oidcContext,
//        tokenAudience = BOM.consentProvider,
//        claimsJsonConverter = GsonClaimsConverter
//    )
//
//    describe("Issue consent token") {
//
//        var token = ""
//        val request = OidcAuthorizeRequest.Builder().also { b ->
//            b.client = BOM.client
//            b.scopes = mutableSetOf("foo", "bar")
//            b.maxAge = 3600
//            b.session.subject = "foo@bar.com"
//            b.session.authTime = LocalDateTime.now().minusSeconds(5)
//        }.build()
//
//        it("should generate token") {
//            token = strategy.generateConsentTokenRequest(request)
//        }
//
//        it("consent provider should be able to decode token") {
//            val claims = JwtConsumerBuilder().also { b ->
//                b.setRequireJwtId()
//                b.setVerificationKey(BOM.jwks.findJsonWebKey(null, null, Use.SIGNATURE, null).resolvePublicKey())
//                b.setExpectedIssuer(BOM.oidcContext.authorizeEndpointUrl)
//                b.setExpectedAudience(BOM.consentProvider)
//            }.build().processToClaims(token)
//            Assertions.assertThat(claims.subject).isEqualTo("foo@bar.com")
//            Assertions.assertThat(claims.getStringClaimValue(ConsentTokenClaim.clientName)).isEqualTo(BOM.client.name)
//            Assertions.assertThat(claims.getStringClaimValue(Param.scope)).contains("foo", "bar")
//        }
//    }
//
//    describe("Decode response token") {
//        val consentToken = generateResponseToken()
//        var claims = JwtClaims()
//
//        it("strategy should be able to process token") {
//            claims = strategy.decodeConsentTokenResponse(consentToken)
//        }
//
//        it("idTokenClaims should reflect authentication status") {
//            Assertions.assertThat(claims.subject).isEqualTo("foo@bar.com")
//        }
//    }
//}) {
//
//    private object BOM {
//        const val consentProvider = "https://login.nix.com"
//
//        val jwks = JsonWebKeySet().also { jwks ->
//            jwks.addJsonWebKey(RsaJwkGenerator.generateJwk(2048).also { k ->
//                k.keyId = "3a400f6f-d66e-4734-b272-c597d147e9ad"
//                k.use = Use.SIGNATURE
//                k.algorithm = JwtSigningAlgorithm.RS256.algorithmIdentifier
//            })
//            jwks.addJsonWebKey(RsaJwkGenerator.generateJwk(2048).also { k ->
//                k.keyId = "a363e5aa-d29e-4ea9-a8b0-f7149ddc0f1f"
//                k.use = Use.ENCRYPTION
//                k.algorithm = JweKeyManagementAlgorithm.RSA1_5.algorithmIdentifier
//            })
//        }
//
//        val oidcContext = mock<ServerContext> {
//            onGeneric { authorizeEndpointUrl } doReturn "https://nix.com/oauth/authorize"
//            onGeneric { masterJsonWebKeySet } doReturn jwks
//        }
//
//        val client = mock<OidcClient> {
//            onGeneric { id } doReturn "777aaf77-50be-44bc-afcb-853192c2918b"
//            onGeneric { name } doReturn "Test Client"
//        }
//    }
//
//    fun generateResponseToken(): String {
//        val jwt = JsonWebSignature().also { jws ->
//            jws.setAlgorithmConstraints(JwtSigningAlgorithm.None.whitelisted())
//            jws.algorithmHeaderValue = JwtSigningAlgorithm.None.algorithmIdentifier
//            jws.payload = JwtClaims().also { c ->
//                c.setGeneratedJwtId()
//                c.setIssuedAtToNow()
//                c.setExpirationTimeMinutesInTheFuture(10f)
//                c.issuer = BOM.consentProvider
//                c.setAudience(BOM.oidcContext.authorizeEndpointUrl)
//                c.subject = "foo@bar.com"
//                c.setClaim(ConsentTokenClaim.scope, "foo bar")
//                c.setClaim(ConsentTokenClaim.remember, 1018080)
//            }.toJson()
//        }.compactSerialization
//
//        return JsonWebEncryption().also { jwe ->
//            jwe.contentTypeHeaderValue = "JWT"
//            jwe.setPlaintext(jwt)
//            jwe.encryptionMethodHeaderParameter = JweContentEncodingAlgorithm.A128GCM.algorithmIdentifier
//            jwe.algorithmHeaderValue = JweKeyManagementAlgorithm.RSA1_5.algorithmIdentifier
//            jwe.key = BOM.jwks.mustKeyForJweKeyManagement(JweKeyManagementAlgorithm.RSA1_5).resolvePublicKey()
//        }.compactSerialization
//    }
//}