package io.imulab.nix.server.oidc

import io.imulab.nix.oidc.claim.ClaimInfo
import io.imulab.nix.oidc.claim.Claims
import io.imulab.nix.oidc.reserved.StandardClaim
import org.assertj.core.api.Assertions.assertThat
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object ClaimsJsonConverterSpec : Spek({

    val expectJson = "{\"userinfo\":{\"given_name\":{\"essential\":true},\"nickname\":null,\"email_verified\":{\"essential\":true},\"picture\":null,\"http://example.info/idTokenClaims/groups\":null},\"id_token\":{\"auth_time\":{\"essential\":true},\"acr\":{\"essential\":false,\"value\":\"urn:mace:incommon:iap:silver\"}}}\n"

    describe("serialize json") {
        it("should produce correct json") {
            val claims = Claims(
                userInfo = mapOf(
                    StandardClaim.givenName to ClaimInfo(essential = true),
                    StandardClaim.nickname to null,
                    StandardClaim.emailVerified to ClaimInfo(essential = true),
                    StandardClaim.picture to null,
                    "http://example.info/idTokenClaims/groups" to null
                ),
                idToken = mapOf(
                    "auth_time" to ClaimInfo(essential = true),
                    "acr" to ClaimInfo(values = listOf("urn:mace:incommon:iap:silver"))
                )
            )

            val json = GsonClaimsConverter.toJson(claims)
            assertThat(json).isEqualTo(expectJson)
        }
    }

    describe("deserialize json") {
        it("should produce correct idTokenClaims object") {
            val claims = GsonClaimsConverter.fromJson(expectJson)

            assertThat(claims.userInfo).isNotNull
            assertThat(claims.idToken).isNotNull

            assertThat(claims.userInfo!![StandardClaim.givenName]).isNotNull
                .extracting { it!!.essential }.isEqualTo(true)
            assertThat(claims.userInfo!!).containsKey(StandardClaim.nickname)
            assertThat(claims.userInfo!![StandardClaim.nickname]).isNull()
            assertThat(claims.userInfo!![StandardClaim.emailVerified]).isNotNull
                .extracting { it!!.essential }.isEqualTo(true)
            assertThat(claims.userInfo!!).containsKey(StandardClaim.picture)
            assertThat(claims.userInfo!![StandardClaim.picture]).isNull()
            assertThat(claims.userInfo!!).containsKey("http://example.info/idTokenClaims/groups")
            assertThat(claims.userInfo!!["http://example.info/idTokenClaims/groups"]).isNull()

            assertThat(claims.idToken!!["auth_time"]).isNotNull
                .extracting { it!!.essential }.isEqualTo(true)
            assertThat(claims.idToken!!["acr"]).isNotNull
                .extracting { it!!.essential }.isEqualTo(false)
            assertThat(claims.idToken!!["acr"]!!.values).hasSize(1).contains("urn:mace:incommon:iap:silver")
        }
    }
})