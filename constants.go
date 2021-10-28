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

const sessionCookieName = "verify-session"
const sessionMaxAge     = 600
const sessionStateKey   = "state"
const sessionUserKey    = "user"
const sessionUrlKey     = "original-url"

/*
 * HTTP server constants.
 */

const httpsPort         = 7443
const authUri           = "/auth"
const loginUri          = "/login"
const logoutUri         = "/logout"
const urlArg            = "url"
const namespaceHdr      = "X-Namespace"
const verifySecretHdr   = "X-Verify-Secret"
const urlRootHdr        = "X-URL-Root"
const logoutRedirectHdr = "X-Logout-Redirect"

/*****************************************************************************/

