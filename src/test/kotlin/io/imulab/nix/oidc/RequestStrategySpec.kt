package io.imulab.nix.oidc

//object RequestStrategySpec: Spek({
//
//    val strategy = RequestStrategy(
//        repository = BOM.repository,
//        httpClient = HttpClient(Apache),
//        jsonWebKeySetStrategy = BOM.jwksStrategy,
//        serverContext = BOM.serverContext
//    )
//
//    fun expectJwtClaimsFromValue(request: String, client: OidcClient) {
//        val expected = BOM.testClaims
//        val actual = runBlocking { strategy.resolveRequest(request, "", client) }
//        assertThat(actual.toJson()).isEqualTo(expected.toJson())
//    }
//
//    fun expectJwtClaimsFromReference(requestUri: String, client: OidcClient) {
//        val expected = BOM.testClaims
//        val actual = runBlocking { strategy.resolveRequest("", requestUri, client) }
//        assertThat(actual.toJson()).isEqualTo(expected.toJson())
//    }
//
//    describe("resolve signed only request object from parameter") {
//
//        val request = BOM.createSignedRequest()
//        val client = mock<OidcClient> {
//            onGeneric { requestObjectSigningAlgorithm } doReturn JwtSigningAlgorithm.RS256
//            onGeneric { requestObjectEncryptionAlgorithm } doReturn JweKeyManagementAlgorithm.None
//            onGeneric { requestObjectEncryptionEncoding } doReturn JweContentEncodingAlgorithm.None
//        }
//
//        it("should resolve jwt idTokenClaims") { expectJwtClaimsFromValue(request, client) }
//    }
//
//    describe("resolve signed and encrypted request object from parameter") {
//        val request = BOM.createSignedRequest().let { BOM.createEncryptedRequest(it) }
//        val client = mock<OidcClient> {
//            onGeneric { requestObjectSigningAlgorithm } doReturn JwtSigningAlgorithm.RS256
//            onGeneric { requestObjectEncryptionAlgorithm } doReturn JweKeyManagementAlgorithm.RSA1_5
//            onGeneric { requestObjectEncryptionEncoding } doReturn JweContentEncodingAlgorithm.A256GCM
//        }
//
//        it("should resolve jwt idTokenClaims") { expectJwtClaimsFromValue(request, client) }
//    }
//
//    describe("resolve encrypted only request object from parameter") {
//        val request = BOM.createPlainRequest().let { BOM.createEncryptedRequest(it) }
//        val client = mock<OidcClient> {
//            onGeneric { requestObjectSigningAlgorithm } doReturn JwtSigningAlgorithm.None
//            onGeneric { requestObjectEncryptionAlgorithm } doReturn JweKeyManagementAlgorithm.RSA1_5
//            onGeneric { requestObjectEncryptionEncoding } doReturn JweContentEncodingAlgorithm.A256GCM
//        }
//
//        it("should resolve jwt idTokenClaims") { expectJwtClaimsFromValue(request, client) }
//    }
//
//    describe("resolve naked request object from parameter") {
//        val request = BOM.createPlainRequest()
//        val client = mock<OidcClient> {
//            onGeneric { requestObjectSigningAlgorithm } doReturn JwtSigningAlgorithm.None
//            onGeneric { requestObjectEncryptionAlgorithm } doReturn JweKeyManagementAlgorithm.RSA1_5
//            onGeneric { requestObjectEncryptionEncoding } doReturn JweContentEncodingAlgorithm.A256GCM
//        }
//
//        it("should resolve jwt idTokenClaims") { expectJwtClaimsFromValue(request, client) }
//    }
//
//    describe("resolve request object from repository") {
//        val client = mock<OidcClient> {
//            onGeneric { requestObjectSigningAlgorithm } doReturn JwtSigningAlgorithm.RS256
//            onGeneric { requestObjectEncryptionAlgorithm } doReturn JweKeyManagementAlgorithm.None
//            onGeneric { requestObjectEncryptionEncoding } doReturn JweContentEncodingAlgorithm.None
//            onGeneric { requestUris } doReturn listOf("https://client.test.com/sample.jwt")
//        }
//
//        it("should resolve jwt idTokenClaims") {
//            expectJwtClaimsFromReference("https://client.test.com/sample.jwt", client)
//        }
//    }
//
//    describe("resolve request object from remote") {
//        val server = WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort())
//        val request = BOM.createSignedRequest()
//        val hash = Base64.getUrlEncoder().withoutPadding().encodeToString(
//            MessageDigest.getInstance("SHA-256").digest(request.toByteArray())
//        )
//
//        beforeGroup {
//            server.start()
//            listOf("/test.jwt", "/test.jwt#$hash", "/test.jwt#badhash").forEach {
//                server.stubFor(
//                    WireMock.get(WireMock.urlEqualTo(it))
//                        .willReturn(WireMock.aResponse().withStatus(200).withBody(request)
//                        ))
//            }
//        }
//
//        it("should resolve jwt idTokenClaims") {
//            val client = mock<OidcClient> {
//                onGeneric { requestObjectSigningAlgorithm } doReturn JwtSigningAlgorithm.RS256
//                onGeneric { requestObjectEncryptionAlgorithm } doReturn JweKeyManagementAlgorithm.None
//                onGeneric { requestObjectEncryptionEncoding } doReturn JweContentEncodingAlgorithm.None
//                onGeneric { requestUris } doReturn listOf("${server.baseUrl()}/test.jwt")
//            }
//            expectJwtClaimsFromReference("${server.baseUrl()}/test.jwt", client)
//        }
//
//        it("should resolve jwt idTokenClaims, with hash checked") {
//            val client = mock<OidcClient> {
//                onGeneric { requestObjectSigningAlgorithm } doReturn JwtSigningAlgorithm.RS256
//                onGeneric { requestObjectEncryptionAlgorithm } doReturn JweKeyManagementAlgorithm.None
//                onGeneric { requestObjectEncryptionEncoding } doReturn JweContentEncodingAlgorithm.None
//                onGeneric { requestUris } doReturn listOf("${server.baseUrl()}/test.jwt#$hash")
//            }
//            expectJwtClaimsFromReference("${server.baseUrl()}/test.jwt#$hash", client)
//        }
//
//        it("should catch bad hash") {
//            val client = mock<OidcClient> {
//                onGeneric { requestObjectSigningAlgorithm } doReturn JwtSigningAlgorithm.RS256
//                onGeneric { requestObjectEncryptionAlgorithm } doReturn JweKeyManagementAlgorithm.None
//                onGeneric { requestObjectEncryptionEncoding } doReturn JweContentEncodingAlgorithm.None
//                onGeneric { requestUris } doReturn listOf("${server.baseUrl()}/test.jwt#badhash")
//            }
//
//            assertThatExceptionOfType(OAuthException::class.java)
//                .isThrownBy {
//                    runBlocking {
//                        strategy.resolveRequest("", "${server.baseUrl()}/test.jwt#badhash", client)
//                    }
//                }
//        }
//
//        afterGroup {
//            server.stop()
//        }
//    }
//
//}) {
//    private object BOM {
//
//        val clientKeySet: JsonWebKeySet by lazy {
//            JsonWebKeySet().also { s ->
//                s.addJsonWebKey(RsaJwkGenerator.generateJwk(2048).also { k ->
//                    k.use = Use.SIGNATURE
//                    k.keyId = "f4781676-02ca-49d2-a4bd-69372f0d0207"
//                })
//            }
//        }
//
//        val serverKeySet: JsonWebKeySet by lazy {
//            JsonWebKeySet().also { s ->
//                s.addJsonWebKey(RsaJwkGenerator.generateJwk(2048).also { k ->
//                    k.use = Use.ENCRYPTION
//                    k.keyId = "d127caaa-12aa-4f38-9145-914c233a7c03"
//                })
//            }
//        }
//
//        val serverContext = mock<OidcContext> {
//            onGeneric { issuerUrl } doReturn "https://test.com"
//            onGeneric { masterJsonWebKeySet } doReturn serverKeySet
//        }
//
//        val jwksStrategy = mock<JsonWebKeySetStrategy> {
//            onBlocking { resolveKeySet(any()) } doReturn clientKeySet
//        }
//
//        val testClaims = JwtClaims().also { c ->
//            c.setGeneratedJwtId()
//            c.setExpirationTimeMinutesInTheFuture(60f)
//            c.setIssuedAtToNow()
//            c.issuer = "RequestStrategySpec"
//            c.setAudience(serverContext.issuerUrl)
//            c.setStringClaim("foo", "bar")
//        }
//
//        fun createSignedRequest(): String {
//            return JsonWebSignature().also { jws ->
//                jws.payload = testClaims.toJson()
//                jws.keyIdHeaderValue = clientKeySet.jsonWebKeys.first().keyId
//                jws.key = clientKeySet.jsonWebKeys.first().resolvePrivateKey()
//                jws.algorithmHeaderValue = JwtSigningAlgorithm.RS256.algorithmIdentifier
//            }.compactSerialization
//        }
//
//        fun createPlainRequest(): String {
//            return JsonWebSignature().also { jws ->
//                jws.payload = testClaims.toJson()
//                jws.setAlgorithmConstraints(JwtSigningAlgorithm.None.whitelisted())
//                jws.algorithmHeaderValue = JwtSigningAlgorithm.None.algorithmIdentifier
//            }.compactSerialization
//        }
//
//        fun createEncryptedRequest(request: String): String {
//            return request.also { jwt ->
//                JsonWebEncryption().also { jwe ->
//                    jwe.setPlaintext(jwt)
//                    jwe.contentTypeHeaderValue = "JWT"
//                    jwe.encryptionMethodHeaderParameter = JweContentEncodingAlgorithm.A256GCM.algorithmIdentifier
//                    jwe.algorithmHeaderValue = JweKeyManagementAlgorithm.RSA1_5.algorithmIdentifier
//                    jwe.key = serverKeySet.jsonWebKeys.first().resolvePublicKey()
//                }.compactSerialization
//            }
//        }
//
//        val repository = mock<CachedRequestRepository> {
//            onBlocking { find(argThat { this.startsWith("https://client.test.com/sample.jwt") }) } doAnswer {
//                val request = createSignedRequest()
//                CachedRequest(
//                    requestUri = "https://client.test.com/sample.jwt",
//                    request = request,
//                    hash = String(MessageDigest.getInstance("SHA-256").digest(request.toByteArray()))
//                )
//            }
//        }
//    }
//}