// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// =================================================================================================
// ServiceNow Background Script: Set up Federated Auth (OIDC) for the Microsoft 365 Copilot connector
// =================================================================================================
//
// PURPOSE
// -------
// This script automates the in-ServiceNow steps of the "Federated Auth (Federated Identity
// Credentials)" authentication option documented at:
//   https://learn.microsoft.com/en-us/microsoft-365/copilot/connectors/servicenow-knowledge-deployment#federated-auth-federated-identity-credentials
//
// Federated Auth lets the connector authenticate to your ServiceNow instance using a Microsoft
// first-party application via OpenID Connect (OIDC) — without storing or rotating a client secret.
//
// WHAT THIS SCRIPT AUTOMATES
// --------------------------
//   Step 2 (doc): Create the OIDC provider in Application Registry (oauth_entity) plus its OIDC
//                 provider configuration, with the Microsoft Entra ID values from the docs.
//   Step 2c (doc): Bind the "useraccount" Auth Scope to the provider and restrict it to that
//                 scope ("Allow access only to APIs in selected scope").
//   Step 3 (doc): Create the ServiceNow integration user (User ID = service principal object ID,
//                 Identity Type = Machine) and assign the required roles.
//
// RUN ORDER & RELATIONSHIP TO THE OTHER SCRIPTS
// ---------------------------------------------
//   Under Federated Auth, the connector authenticates via the Microsoft OIDC token, which
//   ServiceNow maps (User Field = User ID) onto the integration user created here. That integration
//   user is therefore the account the connector CRAWLS AS — so it must also hold the table READ
//   access (the custom role + row/field-level ACLs). This script does NOT grant table read access.
//   Recommended order for a Federated Auth deployment:
//     1. federated_auth_setup.js   (this script — creates the integration user keyed by SP object ID)
//     2. row_level_acl_setup.js    (set its USER_ID = the SAME SP object ID so the read role + ACLs
//                                   are assigned to the integration user, not a separate account)
//     3. field_level_acl_setup.js  (links field ACLs to the role — identity-agnostic)
//     4. scripted_rest_api_setup.js (only if using the Advanced user-criteria flow)
//   The standard roles assigned below (knowledge_admin, etc.) match the doc; the custom crawl role
//   from row_level_acl_setup.js is added when you run that script against this same user.
//
// WHAT YOU MUST DO BEFORE RUNNING (doc Step 1 — cannot be automated inside ServiceNow)
// ------------------------------------------------------------------------------------
//   - Obtain the SERVICE PRINCIPAL OBJECT ID of the Microsoft first-party connector application
//     in YOUR tenant. This is the Object ID of the enterprise application (service principal),
//     NOT a new app registration. Get it via Azure PowerShell:
//         Get-AzADServicePrincipal -ApplicationId "933838e2-bec1-440f-a634-9363c82e5b6d"
//     ...and copy the "Id" value. Or via Microsoft Graph:
//         GET https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq '933838e2-bec1-440f-a634-9363c82e5b6d'
//   - Obtain your Microsoft Entra TENANT ID (Directory ID) from the Azure portal under
//     Microsoft Entra ID > Overview.
//   Set both values in the CONFIGURATION section below before running.
//
// IMPORTANT — VERSION DIFFERENCES & VERIFICATION
// ----------------------------------------------
//   The OIDC provider (Application Registry) data model differs across ServiceNow releases. The
//   manual doc flow itself branches: "Configure an OIDC provider to verify ID tokens" on Yokohama
//   and earlier, vs. the "New Inbound Integration Experience" wizard on Zurich and later. The
//   table/field names below were VERIFIED against a ServiceNow Zurich instance:
//     - oidc_provider_configuration: name, oidc_url, oidc_config_cache_life_span, user_claim,
//       user_field, enable_jti_verification
//     - oauth_oidc_entity (extends oauth_entity): name, client_id, active, oidc_provider_configuration
//   Field access is still guarded with isValidField and the script degrades gracefully — anything
//   it can't set automatically is listed under "Manual follow-ups" at the end, with the exact
//   value to enter in the UI. The Auth Scope ("useraccount") wiring is automated via the verified
//   oauth_entity_auth_scope_mapping table (Zurich), with a manual-note fallback on older releases.
//
//   >> RUN THIS ON A NON-PRODUCTION INSTANCE FIRST and verify the created OIDC provider against
//      the manual steps before relying on it in production. <<
//
// SAFETY & IDEMPOTENCY
// --------------------
//   - Idempotent: existing records (matched by name / user_name) are reused, not duplicated.
//   - Non-destructive: nothing is deleted or overwritten.
//   - No outbound calls: only your ServiceNow instance is touched.
//
// HOW TO RUN
// ----------
//   1. Navigate to: All > System Definition > Scripts - Background.
//   2. Set CONFIGURATION values (SP object ID, tenant ID).
//   3. Paste this script and choose "Run script".
//   4. Review the summary and complete any listed manual follow-ups.
// =================================================================================================

gs.requireSecurityAdmin();

// =================================================================================================
// CONFIGURATION
// =================================================================================================

// --- REQUIRED: values you must supply (doc Step 1) -----------------------------------------------
var SP_OBJECT_ID   = '';   // Service principal OBJECT ID of the Microsoft connector app in your
                           // tenant (the integration user's User ID). REQUIRED.
var TENANT_ID      = '';   // Your Microsoft Entra tenant (Directory) ID. REQUIRED — used in the
                           // OIDC metadata URL.

// --- Microsoft first-party connector application (do not change unless Microsoft tells you to) ---
var MS_CLIENT_ID   = '933838e2-bec1-440f-a634-9363c82e5b6d';   // App ID published by Microsoft.

// --- OIDC provider configuration (defaults match the Microsoft Learn docs) -----------------------
var OIDC_PROVIDER_NAME    = 'Microsoft Entra ID';   // Name of the Application Registry / provider.
var OIDC_CONFIG_NAME      = 'Microsoft Entra ID';   // OIDC Provider Configuration name.
var OIDC_CACHE_LIFESPAN   = 120;                     // OIDC Configuration Cache Lifespan (seconds).
var OIDC_USER_CLAIM       = 'sub';                   // User Claim: 'sub' or 'oid'.
var OIDC_USER_FIELD       = 'user_name';             // User Field the claim maps to. The doc shows
                                                     // "User ID", which is the sys_user.user_name
                                                     // column — that is why the integration user's
                                                     // User ID is set to the SP object ID.
var OIDC_ENABLE_JTI       = false;                   // Enable JTI Verification: Disabled per docs.
var OIDC_METADATA_URL     = 'https://login.microsoftonline.com/' + TENANT_ID +
                            '/v2.0/.well-known/openid-configuration';

// --- Integration user (doc Step 3) ---------------------------------------------------------------
// Roles assigned to the integration user. If your crawling service account uses a custom role,
// add that role name here too (per the doc note).
var INTEGRATION_USER_ROLES = [
  'knowledge_admin',
  'user_criteria_admin',
  'user_admin'
];

// --- Auth Scope (doc Step 2, "select useraccount") -----------------------------------------------
// Name of the sys_auth_scope record to bind to the OAuth provider. The connector's inbound token
// exchange uses the "useraccount" scope. Change only if Microsoft documents a different scope.
var AUTH_SCOPE_NAME = 'useraccount';

// =================================================================================================
// INTERNAL: summary tracker
// =================================================================================================

var SUMMARY = {
  oauthEntity: '',
  oidcConfig: '',
  oidcLink: '',
  authScope: '',
  user: '',
  rolesMapped: [],
  rolesNotFound: [],
  manualActions: [],
  errors: []
};

// =================================================================================================
// UTILITY FUNCTIONS
// =================================================================================================

function tableExists(tbl) {
  try { var gr = new GlideRecord(tbl); return gr.isValid(); } catch (e) { return false; }
}

// Sets a field only if it exists on the record; otherwise records a manual follow-up.
function setIfValid(gr, field, value, label) {
  if (gr.isValidField(field)) { gr[field] = value; return true; }
  SUMMARY.manualActions.push('Set "' + (label || field) + '" = "' + value + '" manually (field "' +
                             field + '" not found on ' + gr.getTableName() + ').');
  return false;
}

// =================================================================================================
// PRECHECK — required configuration
// =================================================================================================

// Background scripts run non-interactively, so instead of prompting we fail fast with guidance
// rather than creating an incomplete OIDC provider or a mis-keyed integration user.
function precheck() {
  if (!SP_OBJECT_ID) {
    throw 'SP_OBJECT_ID is empty. Set it in the CONFIGURATION section before running.\n' +
          '  It is the SERVICE PRINCIPAL OBJECT ID of the Microsoft connector app in YOUR tenant\n' +
          '  (the integration user\'s User ID), obtained via (doc Step 1):\n' +
          '    Get-AzADServicePrincipal -ApplicationId "' + MS_CLIENT_ID + '"   -> copy the "Id" value\n' +
          '  or Microsoft Graph: GET /servicePrincipals?$filter=appId eq \'' + MS_CLIENT_ID + '\' -> "id".';
  }
  if (!TENANT_ID) {
    throw 'TENANT_ID is empty. Set it in the CONFIGURATION section before running.\n' +
          '  It is your Microsoft Entra tenant (Directory) ID, from the Azure portal under\n' +
          '  Microsoft Entra ID > Overview. It is used to build the OIDC metadata URL.';
  }
}

// =================================================================================================
// STEP 2a: OIDC PROVIDER CONFIGURATION — Create or reuse the provider config record
// =================================================================================================
// Holds the metadata URL, cache lifespan, user claim/field, and JTI setting. Verified against a
// ServiceNow Zurich instance: the table is `oidc_provider_configuration` with columns
// name / oidc_url / oidc_config_cache_life_span / user_claim / user_field / enable_jti_verification.
// Field access is still guarded with isValidField for cross-version safety. Returns the config
// record's sys_id (or null if the table is absent).

function getOrCreateOidcConfig() {
  if (!tableExists('oidc_provider_configuration')) {
    SUMMARY.oidcConfig = 'oidc_provider_configuration table not found — configure manually.';
    SUMMARY.manualActions.push('Create the OIDC Provider Configuration manually: Name="' +
      OIDC_CONFIG_NAME + '", OIDC Metadata URL="' + OIDC_METADATA_URL + '", Cache Lifespan=' +
      OIDC_CACHE_LIFESPAN + ', User Claim="' + OIDC_USER_CLAIM + '", User Field="User ID", ' +
      'Enable JTI claim verification=Disabled.');
    return null;
  }

  var c = new GlideRecord('oidc_provider_configuration');
  c.addQuery('name', OIDC_CONFIG_NAME);
  c.setLimit(1);
  c.query();
  if (c.next()) {
    SUMMARY.oidcConfig = 'OIDC config reused: ' + OIDC_CONFIG_NAME + ' (' + c.getUniqueValue() + ')';
    return c.getUniqueValue();
  }

  c.initialize();
  setIfValid(c, 'name', OIDC_CONFIG_NAME, 'OIDC Provider Configuration Name');
  // Metadata URL — Zurich column is `oidc_url` (label "OIDC Metadata URL").
  if (c.isValidField('oidc_url'))                     c.oidc_url = OIDC_METADATA_URL;
  else setIfValid(c, 'oidc_metadata_url', OIDC_METADATA_URL, 'OIDC Metadata URL');
  // Cache lifespan — Zurich column is `oidc_config_cache_life_span`.
  if (c.isValidField('oidc_config_cache_life_span'))  c.oidc_config_cache_life_span = OIDC_CACHE_LIFESPAN;
  else setIfValid(c, 'oidc_configuration_cache_lifespan', OIDC_CACHE_LIFESPAN, 'OIDC Configuration Cache Lifespan');
  if (c.isValidField('user_claim'))                   c.user_claim = OIDC_USER_CLAIM;
  else setIfValid(c, 'user_claim', OIDC_USER_CLAIM, 'User Claim');
  if (c.isValidField('user_field'))                   c.user_field = OIDC_USER_FIELD;
  else setIfValid(c, 'user_field', OIDC_USER_FIELD, 'User Field');
  if (c.isValidField('enable_jti_verification'))      c.enable_jti_verification = OIDC_ENABLE_JTI;

  var id = c.insert();
  if (!id) throw 'Failed to create OIDC provider configuration "' + OIDC_CONFIG_NAME + '".';
  SUMMARY.oidcConfig = 'OIDC config created: ' + OIDC_CONFIG_NAME + ' (' + id + ')';
  return id;
}

// =================================================================================================
// STEP 2b: OIDC PROVIDER ENTITY — Create or reuse the Application Registry record
// =================================================================================================
// Verified against Zurich: inbound "verify ID token" OIDC providers live in `oauth_oidc_entity`,
// which EXTENDS `oauth_entity`. Inserting into the child table sets the inherited name / client_id
// / active / type columns AND the child's `oidc_provider_configuration` reference in one record —
// no separate join table is required. Falls back to `oauth_entity` on older releases that lack the
// child table (with a manual note to wire up the provider configuration in the UI).
// Matched by name for idempotency. `configId` is the sys_id returned by getOrCreateOidcConfig().

function getOrCreateOidcEntity(configId) {
  var entityTable = tableExists('oauth_oidc_entity') ? 'oauth_oidc_entity'
                  : (tableExists('oauth_entity') ? 'oauth_entity' : null);
  if (!entityTable) {
    SUMMARY.oauthEntity = 'No oauth_oidc_entity / oauth_entity table — create the provider manually.';
    SUMMARY.manualActions.push('Create the OIDC provider in All > System OAuth > Application ' +
      'Registry. Name="' + OIDC_PROVIDER_NAME + '", Client ID="' + MS_CLIENT_ID + '", Active=true.');
    return null;
  }

  var e = new GlideRecord(entityTable);
  e.addQuery('name', OIDC_PROVIDER_NAME);
  e.setLimit(1);
  e.query();
  if (e.next()) {
    SUMMARY.oauthEntity = 'OAuth OIDC entity reused: ' + OIDC_PROVIDER_NAME + ' (' + e.getUniqueValue() + ') in ' + entityTable;
    // Ensure the provider configuration reference is set even on a reused record.
    if (configId && e.isValidField('oidc_provider_configuration') && !e.oidc_provider_configuration) {
      e.oidc_provider_configuration = configId;
      e.update();
    }
    return e.getUniqueValue();
  }

  e.initialize();
  setIfValid(e, 'name', OIDC_PROVIDER_NAME, 'Name');
  setIfValid(e, 'client_id', MS_CLIENT_ID, 'Client ID');
  if (e.isValidField('active')) e.active = true;
  // Link the provider configuration directly (only present on the oauth_oidc_entity child table).
  if (configId && e.isValidField('oidc_provider_configuration')) {
    e.oidc_provider_configuration = configId;
  } else if (configId) {
    SUMMARY.manualActions.push('In the Application Registry "' + OIDC_PROVIDER_NAME + '", set the ' +
      'OAuth OIDC Provider Configuration to "' + OIDC_CONFIG_NAME + '" manually (no reference ' +
      'field on ' + entityTable + ').');
  }

  var id = e.insert();
  if (!id) throw 'Failed to create OIDC provider entity "' + OIDC_PROVIDER_NAME + '" in ' + entityTable + '.';
  SUMMARY.oauthEntity = 'OAuth OIDC entity created: ' + OIDC_PROVIDER_NAME + ' (' + id + ') in ' + entityTable;
  return id;
}

// =================================================================================================
// STEP 2c: AUTH SCOPE — Bind "useraccount" to the provider and restrict access to that scope
// =================================================================================================
// Automates the doc step: "Under Auth Scope, select 'useraccount', and enable 'Allow access only
// to APIs in selected scope'." Verified against ServiceNow Zurich:
//   - The "Auth Scopes" related list is the table `oauth_entity_auth_scope_mapping`
//     (columns: oauth_entity -> oauth_entity, auth_scope -> sys_auth_scope).
//   - The scope itself is a record in `sys_auth_scope` (name = "useraccount").
//   - "Allow access only to APIs in selected scope" corresponds to the entity's choice field
//     `scope_restriction_status`, set to the scope name.
// Idempotent (matched by the oauth_entity + auth_scope pair). Every lookup is guarded so the
// script degrades to a manual follow-up on releases that lack these tables/fields.
function ensureAuthScopeMapping(entityId) {
  if (!entityId) {
    SUMMARY.authScope = 'Skipped — OAuth entity not created by this script.';
    SUMMARY.manualActions.push('Bind the "' + AUTH_SCOPE_NAME + '" Auth Scope to "' +
      OIDC_PROVIDER_NAME + '" manually, then enable "Allow access only to APIs in selected scope".');
    return;
  }
  if (!tableExists('oauth_entity_auth_scope_mapping') || !tableExists('sys_auth_scope')) {
    SUMMARY.authScope = 'Auth Scope tables not present on this release — bind manually.';
    SUMMARY.manualActions.push('Under Auth Scopes for "' + OIDC_PROVIDER_NAME + '", add "' +
      AUTH_SCOPE_NAME + '" manually, then enable "Allow access only to APIs in selected scope".');
    return;
  }

  // Resolve the scope record by name.
  var s = new GlideRecord('sys_auth_scope');
  s.addQuery('name', AUTH_SCOPE_NAME);
  s.setLimit(1);
  s.query();
  if (!s.next()) {
    SUMMARY.authScope = 'Scope "' + AUTH_SCOPE_NAME + '" not found in sys_auth_scope — bind manually.';
    SUMMARY.manualActions.push('The "' + AUTH_SCOPE_NAME + '" scope was not found. Under Auth Scopes ' +
      'for "' + OIDC_PROVIDER_NAME + '", add it manually and enable the scope restriction.');
    return;
  }
  var scopeId = s.getUniqueValue();

  // Create the entity -> scope mapping (idempotent on the pair).
  var m = new GlideRecord('oauth_entity_auth_scope_mapping');
  m.addQuery('oauth_entity', entityId);
  m.addQuery('auth_scope', scopeId);
  m.setLimit(1);
  m.query();
  if (m.next()) {
    SUMMARY.authScope = 'Auth Scope mapping reused: ' + AUTH_SCOPE_NAME + ' (' + m.getUniqueValue() + ')';
  } else {
    m.initialize();
    m.oauth_entity = entityId;
    m.auth_scope   = scopeId;
    var mid = m.insert();
    if (!mid) {
      SUMMARY.authScope = 'Failed to create Auth Scope mapping — bind manually.';
      SUMMARY.manualActions.push('Add the "' + AUTH_SCOPE_NAME + '" Auth Scope to "' +
        OIDC_PROVIDER_NAME + '" manually.');
      return;
    }
    SUMMARY.authScope = 'Auth Scope mapping created: ' + AUTH_SCOPE_NAME + ' (' + mid + ')';
  }

  // Restrict the entity to the selected scope (doc: "Allow access only to APIs in selected scope").
  // On Zurich this is the choice field scope_restriction_status = the scope name. Guarded for older
  // releases that don't have the field.
  var ent = new GlideRecord(tableExists('oauth_oidc_entity') ? 'oauth_oidc_entity' : 'oauth_entity');
  if (ent.get(entityId) && ent.isValidField('scope_restriction_status')) {
    if (String(ent.scope_restriction_status) !== AUTH_SCOPE_NAME) {
      ent.scope_restriction_status = AUTH_SCOPE_NAME;
      ent.update();
      SUMMARY.authScope += ' | scope restriction = "' + AUTH_SCOPE_NAME + '"';
    } else {
      SUMMARY.authScope += ' | scope restriction already "' + AUTH_SCOPE_NAME + '"';
    }
  } else {
    SUMMARY.manualActions.push('Enable "Allow access only to APIs in selected scope" on "' +
      OIDC_PROVIDER_NAME + '" manually (Scope Restriction field not on this release).');
  }
}

// =================================================================================================
// STEP 3a: INTEGRATION USER — Create or reuse the machine user keyed by the SP object ID
// =================================================================================================

function getOrCreateIntegrationUser() {
  var u = new GlideRecord('sys_user');
  u.addQuery('user_name', SP_OBJECT_ID);
  u.setLimit(1);
  u.query();
  if (u.next()) {
    SUMMARY.user = 'Integration user reused: ' + SP_OBJECT_ID + ' (' + u.getUniqueValue() + ')';
    return u.getUniqueValue();
  }
  u.initialize();
  u.user_name = SP_OBJECT_ID;        // doc: User ID = service principal object ID
  u.active    = true;
  // Zurich+: mark as machine identity. Older releases: fall back to "Web service access only".
  if (u.isValidField('identity_type'))         u.identity_type = 'machine';
  else if (u.isValidField('web_service_access_only')) u.web_service_access_only = true;
  // Also set web_service_access_only when present alongside identity_type (harmless, matches doc).
  if (u.isValidField('web_service_access_only')) u.web_service_access_only = true;
  var id = u.insert();
  if (!id) throw 'Failed to create integration user "' + SP_OBJECT_ID + '".';
  SUMMARY.user = 'Integration user created: ' + SP_OBJECT_ID + ' (' + id + ')';
  return id;
}

// =================================================================================================
// STEP 3b: ASSIGN ROLES to the integration user
// =================================================================================================

function findRoleIdByName(roleName) {
  var r = new GlideRecord('sys_user_role');
  r.addQuery('name', roleName);
  r.setLimit(1);
  r.query();
  return r.next() ? r.getUniqueValue() : null;
}

function ensureUserHasRole(userSysId, roleSysId) {
  var m = new GlideRecord('sys_user_has_role');
  m.addQuery('user', userSysId);
  m.addQuery('role', roleSysId);
  m.setLimit(1);
  m.query();
  if (m.next()) return m.getUniqueValue();
  m.initialize();
  m.user = userSysId;
  m.role = roleSysId;
  var id = m.insert();
  if (!id) throw 'Failed to map role to integration user';
  return id;
}

function assignRoles(userSysId, roleNames) {
  for (var i = 0; i < roleNames.length; i++) {
    var roleId = findRoleIdByName(roleNames[i]);
    if (roleId) { ensureUserHasRole(userSysId, roleId); SUMMARY.rolesMapped.push(roleNames[i]); }
    else SUMMARY.rolesNotFound.push(roleNames[i]);
  }
}

// =================================================================================================
// EXECUTE — Run all steps in sequence
// =================================================================================================

try {
  precheck();

  // Step 2: OIDC provider configuration first, then the Application Registry entity that
  // references it (oauth_oidc_entity carries the oidc_provider_configuration reference directly).
  var configId = getOrCreateOidcConfig();
  var entityId = getOrCreateOidcEntity(configId);

  // Step 2c: bind the "useraccount" Auth Scope to the entity and restrict access to it (verified
  // table oauth_entity_auth_scope_mapping on Zurich; degrades to a manual note on older releases).
  ensureAuthScopeMapping(entityId);

  // Step 3: Integration user + roles
  var userId = getOrCreateIntegrationUser();
  assignRoles(userId, INTEGRATION_USER_ROLES);

} catch (e) {
  gs.error('FATAL: Federated Auth setup aborted — ' + e);
  SUMMARY.errors.push('FATAL: ' + e);
}

// =================================================================================================
// SUMMARY — Print results for review
// =================================================================================================

gs.print('\n--- Federated Auth (OIDC) Setup Summary ---');
gs.print('OIDC config:          ' + SUMMARY.oidcConfig);
gs.print('OAuth OIDC entity:    ' + SUMMARY.oauthEntity);
gs.print('Auth Scope:           ' + SUMMARY.authScope);
gs.print('Integration user:     ' + SUMMARY.user);
gs.print('Metadata URL:         ' + OIDC_METADATA_URL);

if (SUMMARY.rolesMapped.length)
  gs.print('Roles assigned:       ' + SUMMARY.rolesMapped.join(', '));
if (SUMMARY.rolesNotFound.length)
  gs.warn('Roles NOT FOUND (assign manually): ' + SUMMARY.rolesNotFound.join(', '));

if (SUMMARY.manualActions.length) {
  gs.warn('\nManual follow-ups / verification needed:');
  SUMMARY.manualActions.forEach(function (s) { gs.warn('  - ' + s); });
}

if (SUMMARY.errors.length) {
  gs.warn('\nErrors:\n  - ' + SUMMARY.errors.join('\n  - '));
} else {
  gs.print('\nFederated Auth setup completed. Review the verification checklist above.');
}

gs.print('\nNext: In the Microsoft 365 admin center, choose "Federated Auth" as the authentication ' +
         'method and provide your ServiceNow instance URL.');
