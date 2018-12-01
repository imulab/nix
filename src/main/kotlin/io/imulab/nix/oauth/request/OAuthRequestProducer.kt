package io.imulab.nix.oauth.request

/**
 * Provides function to take [OAuthRequestForm] and produce a [OAuthRequest]. Subclasses can call
 * super producers to get a prototype request object and then supply data to its own builder.
 */
interface OAuthRequestProducer {
    suspend fun produce(form: OAuthRequestForm): OAuthRequest
}