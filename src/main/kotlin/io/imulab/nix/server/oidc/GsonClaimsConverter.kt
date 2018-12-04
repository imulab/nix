package io.imulab.nix.server.oidc

import com.google.gson.*
import io.imulab.nix.oauth.error.InvalidRequest
import io.imulab.nix.oidc.claim.ClaimInfo
import io.imulab.nix.oidc.claim.Claims
import io.imulab.nix.oidc.claim.ClaimsJsonConverter
import io.imulab.nix.oidc.reserved.OidcParam
import java.lang.reflect.Type

object GsonClaimsConverter: ClaimsJsonConverter {

    private const val userInfoField = "userinfo"
    private const val idTokenField = "id_token"
    private const val essentialField = "essential"
    private const val valueField = "value"
    private const val valuesField = "values"

    private val gson: Gson

    init {
        gson = GsonBuilder().registerTypeAdapter(Claims::class.java, ClaimsDeserializer())
            .registerTypeAdapter(Claims::class.java, ClaimsSerializer())
            .serializeNulls()
            .create()
    }

    override fun toJson(claims: Claims): String = gson.toJson(claims)

    override fun fromJson(value: String): Claims = gson.fromJson(value, Claims::class.java)

    private class ClaimsSerializer: JsonSerializer<Claims> {

        override fun serialize(src: Claims?, typeOfSrc: Type?, context: JsonSerializationContext?): JsonElement {
            val json = JsonObject()
            if (src != null) {
                if (src.userInfo != null)
                    json.add(userInfoField, buildClaimsMap(src.userInfo!!))
                if (src.idToken != null)
                    json.add(idTokenField, buildClaimsMap(src.idToken!!))
            }
            return json
        }

        private fun buildClaimsMap(m: Map<String, ClaimInfo?>): JsonObject {
            val json = JsonObject()
            m.forEach { t, u ->
                if (u == null)
                    json.add(t, JsonNull.INSTANCE)
                else
                    json.add(t, buildClaimInfo(u))
            }
            return json
        }

        private fun buildClaimInfo(info: ClaimInfo): JsonObject {
            return JsonObject().also { json ->
                json.addProperty(essentialField, info.essential)
                when (info.values.size) {
                    0 -> {}
                    1 -> json.addProperty(valueField, info.values[0])
                    else -> json.add(valuesField, JsonArray().also { array ->
                        info.values.forEach { array.add(it) }
                    })
                }
            }
        }
    }

    private class ClaimsDeserializer: JsonDeserializer<Claims> {

        override fun deserialize(json: JsonElement?, typeOfT: Type?, context: JsonDeserializationContext?): Claims {
            if (json == null)
                return Claims()

            return Claims(
                userInfo = if (json.asJsonObject.has(userInfoField)) {
                    parseClaimsMap(json.asJsonObject.get(userInfoField))
                } else {
                    null
                },
                idToken = if (json.asJsonObject.has(idTokenField)) {
                    parseClaimsMap(json.asJsonObject.getAsJsonObject(idTokenField))
                } else {
                    null
                }
            )
        }

        private fun parseClaimsMap(json: JsonElement): Map<String, ClaimInfo?>? {
            if (json.isJsonNull)
                return null
            else if (!json.isJsonObject)
                throw InvalidRequest.invalid(OidcParam.claims)

            val m = mutableMapOf<String, ClaimInfo?>()
            json.asJsonObject.keySet().forEach { k ->
                val e = json.asJsonObject.get(k)
                when {
                    e.isJsonNull -> m[k] = null
                    e.isJsonObject -> m[k] = parseClaimsInfo(e.asJsonObject)
                    else -> throw InvalidRequest.invalid(OidcParam.claims)
                }
            }
            return m
        }

        private fun parseClaimsInfo(json: JsonObject): ClaimInfo {
            val c = ClaimInfo()

            try {
                if (json.has(essentialField))
                    c.essential = json.getAsJsonPrimitive(essentialField).asBoolean

                if (json.has(valueField))
                    c.values = listOf(json.getAsJsonPrimitive(valueField).asString)
                else if (json.has(valuesField))
                    c.values = json.getAsJsonArray(valueField).map { it.asJsonPrimitive.asString }.toList()
            } catch (e: Exception) {
                throw InvalidRequest.invalid(OidcParam.claims)
            }

            return c
        }
    }
}