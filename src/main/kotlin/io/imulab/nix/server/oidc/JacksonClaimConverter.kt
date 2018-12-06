package io.imulab.nix.server.oidc

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import io.imulab.nix.oauth.error.InvalidRequest
import io.imulab.nix.oidc.claim.ClaimConverter
import io.imulab.nix.oidc.claim.Claims
import io.imulab.nix.oidc.reserved.OidcParam

class JacksonClaimConverter(private val objectMapper: ObjectMapper): ClaimConverter {

    override fun fromJson(json: String): Claims {
        return try {
            Claims(objectMapper.readValue<LinkedHashMap<String, Any>>(json))
        } catch (e: Exception) {
            throw InvalidRequest.invalid(OidcParam.claims)
        }
    }
}