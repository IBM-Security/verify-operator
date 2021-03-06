/*
 * Copyright contributors to the IBM Security Verify Operator project
 */

package main

/*****************************************************************************/

/*
 * Annotation keys.
 */

const appNameKey           = "verify.ibm.com/app.name"
const appUrlKey            = "verify.ibm.com/app.url"
const crNameKey            = "verify.ibm.com/cr.name"
const consentKey           = "verify.ibm.com/consent.action"
const protocolKey          = "verify.ibm.com/protocol"
const idTokenKey           = "verify.ibm.com/idtoken.hdr"
const debugLevelKey        = "verify.ibm.com/debug.level"

/*
 * Secret keys.
 */

const productKey           = "product"
const clientNameKey        = "client_name"
const clientIdKey          = "client_id"
const clientSecretKey      = "client_secret"
const discoveryEndpointKey = "discovery_endpoint"
const secretNamePrefix     = "ibm-security-verify-client-"
const productName          = "ibm-security-verify"

/*
 * Registration constants.
 */

const defaultConsentAction = "always_prompt"
const defaultProtocol      = "https"

/*
 * Session constants.
 */

const maxCacheSize      = 32752
const sessionCookieName = "verify-session"
const sessionStateKey   = "state"
const sessionUserKey    = "user"
const sessionIdTokenKey = "identity"
const sessionUrlKey     = "original-url"
const expiryKey         = "expires"

/*
 * HTTP server constants.
 */

const httpsPort         = 7443
const defSessLifetime   = 3600
const checkUri          = "/check"
const authUri           = "/auth"
const loginUri          = "/login"
const logoutUri         = "/logout"
const urlArg            = "url"

const namespaceHdr      = "X-Namespace"
const verifySecretHdr   = "X-Verify-Secret"
const urlRootHdr        = "X-URL-Root"
const logoutRedirectHdr = "X-Logout-Redirect"
const sessLifetimeHdr   = "X-Session-Lifetime"
const debugLevelHdr     = "X-Debug-Level"
const idTokenHdr        = "x_identity"

/*****************************************************************************/

