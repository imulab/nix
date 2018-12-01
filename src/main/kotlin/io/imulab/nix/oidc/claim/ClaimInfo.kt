package io.imulab.nix.oidc.claim

data class ClaimInfo(var essential: Boolean = false,
                     var values: List<String> = emptyList())