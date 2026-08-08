// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// =================================================================================================
// ServiceNow Background Script: Set up Scripted REST API for Microsoft 365 Copilot Connector
// =================================================================================================
// PURPOSE
// -------
// This script automates the "Set up REST API" steps documented at:
//   https://learn.microsoft.com/en-us/microsoft-365/copilot/connectors/servicenow-knowledge-admin-setup#set-up-rest-api
//
// When you choose the "Advanced" flow for the ServiceNow Knowledge Copilot connector, the connector
// needs a Scripted REST API endpoint in your ServiceNow instance to fetch user criteria. This script
// creates that endpoint and configures all required security settings in a single run.

gs.requireSecurityAdmin();

// =================================================================================================
// CONFIGURATION
// =================================================================================================
// Edit these values only if your setup requires different names or a custom role.
// For most deployments, the defaults below match the Microsoft Learn documentation exactly.

var ROLE_NAME                 = 'copilot_connector';         // Role to grant execute access on the endpoint.
                                                            // Defaults to 'copilot_connector' — the SAME role the
                                                            // row-level & field-level ACL scripts grant to the crawl
                                                            // account, so the connector's service account can call
                                                            // this endpoint. Set to '' to fall back to the built-in
                                                            // 'admin' role (NOT recommended: the crawl account is
                                                            // intentionally not an admin).

var ACL_NAME                  = 'Microsoft Copilot';        // Name of the ACL to create.
                                                            // Must be "Microsoft Copilot" per the docs.

var API_NAME                  = 'Microsoft Copilot';        // Display name of the Scripted REST API.

var API_ID_VALUE              = 'microsoft_copilot';        // API ID used in the endpoint URL path.
                                                            // The final URL will be:
                                                            // /api/<namespace>/microsoft_copilot/user_criteria

var RESOURCE_NAME             = 'GetAllUserCriteria';       // Name of the API resource.
var RESOURCE_PATH             = '/user_criteria';           // Relative path appended to the API base path.

var EXTERNAL_DEFAULT_ACL_NAME = 'Scripted REST External Default';
                                                            // Name of the out-of-the-box ACL that ships with
                                                            // the Scripted REST plugin. This script looks it up
                                                            // by name — it does NOT create it.

// The script that the resource will execute when called.
// It takes a 'user' query parameter (a user sys_id), looks up all active user_criteria records,
// and returns only the criteria sys_ids that match that user. Missing/invalid input returns
// HTTP 400; unexpected errors return HTTP 500.
// This is the exact script from the Microsoft Learn documentation:
//   https://learn.microsoft.com/en-us/microsoft-365/copilot/connectors/servicenow-knowledge-admin-setup#set-up-rest-api
var RESOURCE_SCRIPT = [
  "(function execute (/*RESTAPIRequest*/ request, /*RESTAPIResponse*/ response) {",
  "   // Get query parameters from the request",
  "   var queryParams = request.queryParams;",
  "   // Extract the 'user' sys_id, ensure it's a string or null if not provided",
  "   var userSysId = queryParams.user ? String(queryParams.user) : null;",
  "   var result = []; // Initialize an empty array for the results",
  "   // Check if userSysId was provided",
  "   if (!userSysId) {",
  "       gs.warn(\"UserCriteriaLoader API: 'user' parameter was not provided in the request.\");",
  "       response.setStatus(400);",
  "       return { \"error\": \"User sys_id is required.\" };",
  "   }",
  "   try {",
  "       // Instantiate the UserCriteriaLoader",
  "       var userCriteriaLoader = new sn_uc.UserCriteriaLoader();",
  "       var userCriterias = [];",
  "       var userCriteriaGr = new GlideRecord('user_criteria');",
  "       userCriteriaGr.addQuery('active', true); // Select active records. You can also add any connection scope filter if required",
  "       userCriteriaGr.query();",
  "       while (userCriteriaGr.next()) {",
  "           userCriterias.push(userCriteriaGr.getUniqueValue());",
  "       }",
  "       // Call the recommended API to get only matching criteria sys_ids",
  "       var matchingCriteriaIds = sn_uc.UserCriteriaLoader.getMatchingCriteria(userSysId, userCriterias);",
  "       // Return the array of matching criteria objects",
  "       return matchingCriteriaIds;",
  "   } catch (e) {",
  "       // Log any errors that occur during the process",
  "       gs.error(\"UserCriteriaLoader API: Error processing user criteria for user \" + userSysId + \". Error: \" + e.message);",
  "       response.setStatus(500); // Internal Server Error",
  "       return {",
  "           error_message: \"Error processing user criteria for user \" + userSysId,",
  "           error_details: e.message",
  "       };",
  "   }",
  "})(request, response);"
].join("\n");

// =================================================================================================
// INTERNAL: Summary tracker — collects results from each step for the final report
// =================================================================================================

var SUMMARY = {
  role: '', endpointAcl: '', endpointAclLinked: '',
  externalDefaultAcl: '',
  api: '', apiDefaultAcls: '',
  resource: '', resourceAcls: '',
  manualActions: []
};

// =================================================================================================
// UTILITY FUNCTIONS
// =================================================================================================

// Checks whether a table exists on this instance.
// Used to determine if resources are stored in sys_ws_resource or sys_ws_operation,
// which varies across ServiceNow versions.
function tableExists(tbl) {
  try { var gr = new GlideRecord(tbl); return gr.isValid(); } catch (e) { return false; }
}

// =================================================================================================
// STEP 1: ROLE — Locate or create the role for ACL authorization
// =================================================================================================
// The ACL we create in Step 2 needs a role attached to it. Users who have this role will be
// able to execute the Scripted REST API endpoint.
// - If ROLE_NAME is empty, the script uses the built-in 'admin' role.
// - If ROLE_NAME is set and the role exists, it is reused.
// - If ROLE_NAME is set and the role does not exist, it is created.

function getOrCreateRole(name) {
  if (!name) {
    var adminRole = new GlideRecord('sys_user_role');
    adminRole.addQuery('name', 'admin');
    adminRole.query();
    if (adminRole.next()) {
      SUMMARY.role = 'Using default admin role';
      return adminRole.sys_id.toString();
    }
  }
  var r = new GlideRecord('sys_user_role');
  r.addQuery('name', name);
  r.query();
  if (r.next()) {
    SUMMARY.role = 'Role reused: ' + name;
    return r.sys_id.toString();
  }
  r.initialize();
  r.name = name;
  r.description = name + ' (auto-created for Copilot connector)';
  var id = r.insert();
  if (!id) throw 'Failed to create role: ' + name;
  SUMMARY.role = 'Role created: ' + name;
  return id;
}

// =================================================================================================
// STEP 2: ACL — Create the "Microsoft Copilot" Access Control record
// =================================================================================================
// Creates an ACL of type REST_Endpoint with operation Execute.
// This is the same ACL you would create manually via:
//   All > System Security > Access Control (ACL) > New
// The script checks if an ACL with the same name/type/operation already exists to avoid duplicates.

function findAcl(type, operation, nameValue) {
  var a = new GlideRecord('sys_security_acl');
  a.addQuery('type', type);
  a.addQuery('operation', operation);
  a.addQuery('name', nameValue);
  a.query();
  return a.next() ? a : null;
}

function findAclByName(nameValue) {
  var a = new GlideRecord('sys_security_acl');
  a.addQuery('name', nameValue);
  a.query();
  return a.next() ? a : null;
}

function createEndpointExecuteAcl(nameValue) {
  // Check if this ACL already exists
  var existing = findAcl('REST_Endpoint', 'execute', nameValue);
  if (existing) {
    SUMMARY.endpointAcl = 'Endpoint ACL reused: ' + nameValue + ' (' + existing.sys_id + ')';
    return existing;
  }
  // Create new ACL
  var a = new GlideRecord('sys_security_acl');
  a.initialize();
  a.type            = 'REST_Endpoint';
  a.operation       = 'execute';
  a.name            = nameValue;
  a.active          = true;
  a.admin_overrides = true;
  if (a.isValidField('order')) a.order = 50;
  a.script          = '';
  a.description     = 'REST_Endpoint Execute ACL for ' + nameValue;
  var id = a.insert();
  if (!id) throw 'Failed to insert endpoint ACL: ' + nameValue;
  a.get(id);
  SUMMARY.endpointAcl = 'Endpoint ACL created: ' + nameValue + ' (' + id + ')';
  return a;
}

// =================================================================================================
// STEP 3: LINK ACL TO ROLE — Grant the role execute permission via the ACL
// =================================================================================================
// Creates an entry in the sys_security_acl_role M2M table to associate the ACL with the role.
// Equivalent to adding the role under "Requires Roles" on the ACL form in the UI.

function linkAclToRole(aclId, roleId) {
  var m = new GlideRecord('sys_security_acl_role');
  m.addQuery('sys_security_acl', aclId);
  m.addQuery('sys_user_role', roleId);
  m.query();
  if (m.next()) {
    SUMMARY.endpointAclLinked = 'Endpoint ACL already linked to role';
    return;
  }
  m.initialize();
  m.sys_security_acl = aclId;
  m.sys_user_role    = roleId;
  if (!m.insert()) throw 'Failed to link ACL to role';
  SUMMARY.endpointAclLinked = 'Endpoint ACL linked to role';
}

// =================================================================================================
// STEP 4: FIND the out-of-the-box "Scripted REST External Default" ACL
// =================================================================================================
// This ACL is shipped by ServiceNow as part of the Scripted REST API plugin.
// We do NOT create it — we only look it up so we can assign it alongside "Microsoft Copilot".
// The search uses three fallback strategies (exact name, suffixed name, partial match) to
// handle minor naming variations across ServiceNow versions.

function findExternalDefaultAcl() {
  // Strategy 1: Exact name match (most common)
  var acl = findAclByName(EXTERNAL_DEFAULT_ACL_NAME);
  if (acl) {
    SUMMARY.externalDefaultAcl = 'External Default ACL found: ' + EXTERNAL_DEFAULT_ACL_NAME + ' (' + acl.sys_id + ')';
    return acl.sys_id.toString();
  }
  // Strategy 2: Try with "ACL" suffix (some instances label it differently)
  acl = findAclByName(EXTERNAL_DEFAULT_ACL_NAME + ' ACL');
  if (acl) {
    SUMMARY.externalDefaultAcl = 'External Default ACL found (alt name): ' + acl.name + ' (' + acl.sys_id + ')';
    return acl.sys_id.toString();
  }
  // Strategy 3: Partial name match as a last resort
  var a = new GlideRecord('sys_security_acl');
  a.addQuery('name', 'CONTAINS', 'Scripted REST External Default');
  a.query();
  if (a.next()) {
    SUMMARY.externalDefaultAcl = 'External Default ACL found (partial match): ' + a.name + ' (' + a.sys_id + ')';
    return a.sys_id.toString();
  }
  // Not found — the script will still assign the "Microsoft Copilot" ACL,
  // but will flag this as a manual follow-up.
  SUMMARY.externalDefaultAcl = 'NOT FOUND — will only assign Microsoft Copilot ACL';
  SUMMARY.manualActions.push(
    'OOTB ACL "' + EXTERNAL_DEFAULT_ACL_NAME + '" not found. ' +
    'Add it manually to API Default ACLs and Resource ACLs in the UI.'
  );
  return null;
}

// =================================================================================================
// HELPER: Build a comma-separated ACL sys_id list for glide_list fields
// =================================================================================================
// Both the API (sys_ws_definition) and Resource (sys_ws_operation) store their ACL assignments
// in a glide_list field that accepts comma-separated sys_ids.

function buildAclList(copilotAclId, externalDefaultAclId) {
  if (copilotAclId && externalDefaultAclId) {
    return copilotAclId + ',' + externalDefaultAclId;
  } else if (copilotAclId) {
    return copilotAclId;
  } else if (externalDefaultAclId) {
    return externalDefaultAclId;
  }
  return '';
}

// =================================================================================================
// STEP 5: CREATE or REUSE the Scripted REST API definition
// =================================================================================================
// Creates a new record in sys_ws_definition with:
//   Name: "Microsoft Copilot"  |  API ID: "microsoft_copilot"  |  Active: true
//
// Idempotent: if one or more APIs named "Microsoft Copilot" already exist, the oldest is reused
// (never duplicated). If more than one exists, the extras are flagged for manual cleanup, and a
// mismatched API ID (endpoint URL segment) is reported so you can fix it.
//
// The API ID field name varies across ServiceNow versions:
//   - 'service_id' (most common, label "API ID")
//   - 'api_id' (some versions)
//   - 'base_uri' / 'base_path' (older versions)
// The script probes for each in order and uses the first one found.

function getOrCreateScriptedApi(apiName, apiIdValue) {
  // Find ALL definitions with this name (oldest first) so duplicates are detected, not created.
  var matches = [];
  var probe = new GlideRecord('sys_ws_definition');
  probe.addQuery('name', apiName);
  probe.orderBy('sys_created_on');
  probe.query();
  while (probe.next()) matches.push(probe.sys_id.toString());

  if (matches.length) {
    var d = new GlideRecord('sys_ws_definition');
    d.get(matches[0]); // reuse the oldest match deterministically — never duplicate

    if (matches.length > 1) {
      SUMMARY.manualActions.push(
        'Found ' + matches.length + ' Scripted REST APIs named "' + apiName + '". ' +
        'Reusing the oldest (' + matches[0] + '). Review and delete the duplicate(s): ' +
        matches.slice(1).join(', ')
      );
    }

    // Drift check on the API ID (the endpoint URL segment). Warn only — changing it would alter the
    // endpoint URL and could collide with a duplicate's unique API ID, so it is not auto-changed.
    var idField = d.isValidField('service_id') ? 'service_id' : (d.isValidField('api_id') ? 'api_id' : null);
    if (idField && d.getValue(idField) !== apiIdValue) {
      SUMMARY.manualActions.push(
        'API "' + apiName + '" has ' + idField + ' = "' + d.getValue(idField) + '" but expected "' + apiIdValue +
        '". Endpoint URL may be wrong — verify and fix manually (not auto-changed to avoid URL/uniqueness issues).'
      );
    }

    SUMMARY.api = 'API reused: ' + apiName + ' (' + d.sys_id + ')' +
                  (matches.length > 1 ? ' [' + matches.length + ' duplicates found]' : '');
    return d;
  }

  // None found — create a fresh definition.
  var n = new GlideRecord('sys_ws_definition');
  n.initialize();
  n.name   = apiName;
  n.active = true;

  // Set the API ID using the first valid field name found
  if (n.isValidField('service_id'))       n.service_id = apiIdValue;
  else if (n.isValidField('api_id'))      n.api_id     = apiIdValue;
  else if (n.isValidField('base_uri'))    n.base_uri   = '/' + apiIdValue;
  else if (n.isValidField('base_path'))   n.base_path  = '/' + apiIdValue;
  else SUMMARY.manualActions.push('Set API identifier manually in UI for "' + apiName + '".');

  if (n.isValidField('requires_authentication')) n.requires_authentication = true;

  var id = n.insert();
  if (!id) throw 'Failed to create Scripted REST API: ' + apiName;
  n.get(id);
  SUMMARY.api = 'API created: ' + apiName + ' (' + id + ')';
  return n;
}

// =================================================================================================
// STEP 6: ASSIGN Default ACLs on the Scripted REST API
// =================================================================================================
// Sets the "Default ACLs" field on the API to include BOTH:
//   - "Microsoft Copilot" (the ACL we created in Step 2)
//   - "Scripted REST External Default" (the OOTB ACL found in Step 4)
//
// The field name is 'enforce_acl' (type: glide_list) on most instances.
// Falls back to 'default_acl' for cross-version compatibility.
// These Default ACLs are enforced on any resource under this API that has
// "Requires ACL authorization" enabled and does not override with its own ACLs.

function setApiDefaultAcls(defGR, aclListStr) {
  if (!aclListStr) {
    SUMMARY.apiDefaultAcls = 'No ACLs to assign (both lookups failed).';
    SUMMARY.manualActions.push('Set API Default ACLs manually in UI.');
    return;
  }

  var fieldCandidates = ['enforce_acl', 'default_acl'];
  var fieldUsed = null;
  for (var i = 0; i < fieldCandidates.length; i++) {
    if (defGR.isValidField(fieldCandidates[i])) {
      fieldUsed = fieldCandidates[i];
      break;
    }
  }

  if (fieldUsed) {
    defGR[fieldUsed] = aclListStr;
    defGR.update();
    SUMMARY.apiDefaultAcls = 'API Default ACLs set via "' + fieldUsed + '": ' + aclListStr;
  } else {
    SUMMARY.apiDefaultAcls = 'No ACL field found on sys_ws_definition.';
    SUMMARY.manualActions.push('Set API Default ACLs manually in UI (field not accessible via script).');
  }
}

// =================================================================================================
// STEP 7: CREATE or UPDATE the API resource (GetAllUserCriteria)
// =================================================================================================
// Creates a GET resource at /user_criteria under the Scripted REST API.
// The resource is stored in either sys_ws_resource or sys_ws_operation depending on the
// ServiceNow version. The script checks which table exists and uses the appropriate one.
//
// Idempotent: if the resource already exists under this API, its script and settings are compared
// against the values below and updated IN PLACE only when they differ — the resource is never
// duplicated. If it is already current, nothing is changed. Extra duplicates are flagged.
//
// Configuration set on the resource:
//   - HTTP method: GET
//   - Requires authentication: true
//   - Requires ACL authorization: true
//   - Script: the user criteria lookup script from the Microsoft Learn documentation

function createResourceOrOperation(defGR, resName, relPath, scriptBody) {
  var useRes = tableExists('sys_ws_resource');
  var useOp  = tableExists('sys_ws_operation');
  if (!useRes && !useOp) {
    SUMMARY.manualActions.push('Create resource via UI (no sys_ws_resource/operation table).');
    return null;
  }

  var tbl = useRes ? 'sys_ws_resource' : 'sys_ws_operation';

  function boolTrue(v) { return v == '1' || v == 'true'; }
  function scriptFieldOf(gr) {
    if (gr.isValidField('operation_script')) return 'operation_script';
    if (gr.isValidField('script'))           return 'script';
    return null;
  }

  // Look for an existing resource with this name under this API.
  // NOTE: we match on name only (not path) so an existing resource is UPDATED in place rather than
  // duplicated if its relative path changed. Oldest first for deterministic selection.
  var r = new GlideRecord(tbl);
  r.addQuery('web_service_definition', defGR.sys_id);
  if (r.isValidField('name')) r.addQuery('name', resName);
  r.orderBy('sys_created_on');
  r.query();

  if (r.next()) {
    // -------- EXISTING resource: check for drift and update in place (never duplicate) --------
    var changes = [];
    var sf = scriptFieldOf(r);

    // 1. Script — compare (ignoring CRLF/LF differences) and update ONLY if it actually changed.
    if (sf) {
      var currentScript = (r.getValue(sf) || '').replace(/\r\n/g, '\n');
      if (currentScript !== scriptBody) {
        r.setValue(sf, scriptBody);
        changes.push('script');
      }
    } else {
      SUMMARY.manualActions.push('Paste resource script in UI (script field not accessible).');
    }

    // 2. Relative path
    if (r.isValidField('relative_path')) {
      if (r.getValue('relative_path') !== relPath) { r.relative_path = relPath; changes.push('relative_path'); }
    } else if (r.isValidField('http_path')) {
      if (r.getValue('http_path') !== relPath) { r.http_path = relPath; changes.push('http_path'); }
    }

    // 3. Method + security flags — self-heal to the required values
    if (r.isValidField('http_method') && r.getValue('http_method') !== 'GET') { r.http_method = 'GET'; changes.push('http_method'); }
    if (r.isValidField('requires_authentication')    && !boolTrue(r.getValue('requires_authentication')))    { r.requires_authentication = true;    changes.push('requires_authentication'); }
    if (r.isValidField('requires_acl_authorization') && !boolTrue(r.getValue('requires_acl_authorization'))) { r.requires_acl_authorization = true; changes.push('requires_acl_authorization'); }
    if (r.isValidField('requires_acl')               && !boolTrue(r.getValue('requires_acl')))               { r.requires_acl = true;               changes.push('requires_acl'); }
    if (r.isValidField('active')                     && !boolTrue(r.getValue('active')))                     { r.active = true;                     changes.push('active'); }

    if (changes.length) {
      r.update();
      SUMMARY.resource = 'Resource updated in ' + tbl + ' (' + r.sys_id + ') — changed: ' + changes.join(', ');
    } else {
      SUMMARY.resource = 'Resource already up to date in ' + tbl + ' (' + r.sys_id + ') — no changes';
    }

    // Flag any additional duplicate resources of the same name under this API.
    var dupCount = 0;
    var dup = new GlideRecord(tbl);
    dup.addQuery('web_service_definition', defGR.sys_id);
    if (dup.isValidField('name')) dup.addQuery('name', resName);
    dup.addQuery('sys_id', '!=', r.sys_id.toString());
    dup.query();
    while (dup.next()) dupCount++;
    if (dupCount) {
      SUMMARY.manualActions.push(
        'Found ' + (dupCount + 1) + ' "' + resName + '" resources under this API. ' +
        'Updated one; review and delete the ' + dupCount + ' duplicate(s).'
      );
    }
    return r;
  }

  // -------- No existing resource: create a new one --------
  r = new GlideRecord(tbl);
  r.initialize();
  if (r.isValidField('web_service_definition')) r.web_service_definition = defGR.sys_id;
  if (r.isValidField('name'))           r.name = resName;
  if (r.isValidField('relative_path'))  r.relative_path = relPath;
  else if (r.isValidField('http_path')) r.http_path = relPath;
  r.active = true;

  // HTTP method
  if (r.isValidField('http_method')) r.http_method = 'GET';

  // Security flags — both must be true for ACL enforcement to take effect
  if (r.isValidField('requires_authentication'))    r.requires_authentication    = true;
  if (r.isValidField('requires_acl_authorization')) r.requires_acl_authorization = true;
  if (r.isValidField('requires_acl'))               r.requires_acl               = true;
  // NOTE: The 'enforce_acl' field is a glide_list for ACL references (not a boolean).
  // ACL assignment is handled separately in Step 8 via setResourceAcls().

  // Resource script — the field name varies: 'operation_script' (modern) or 'script'.
  var sfNew = scriptFieldOf(r);
  if (sfNew) r.setValue(sfNew, scriptBody);
  else SUMMARY.manualActions.push('Paste resource script in UI (script field not accessible).');

  var id = r.insert();
  if (!id) throw 'Failed to create resource/operation in ' + tbl;
  r.get(id);
  SUMMARY.resource = 'Resource created in ' + tbl + ' (' + id + ')';
  return r;
}

// =================================================================================================
// STEP 8: ASSIGN ACLs on the Resource
// =================================================================================================
// Sets the "ACLs" field on the resource to include BOTH:
//   - "Microsoft Copilot"
//   - "Scripted REST External Default"
//
// The field name is 'enforce_acl' (type: glide_list) on most instances.
// Falls back to 'override_acl', 'acl', 'default_acl' for cross-version compatibility.
// When both "Requires authentication" and "Requires ACL authorization" are checked on the resource
// AND this ACLs field is populated, ServiceNow evaluates these ACLs to authorize each request.

function setResourceAcls(resGR, aclListStr) {
  if (!resGR || !aclListStr) {
    SUMMARY.resourceAcls = 'No resource or no ACLs to assign.';
    return;
  }

  var fieldCandidates = ['enforce_acl', 'override_acl', 'acl', 'default_acl'];
  var fieldUsed = null;
  for (var i = 0; i < fieldCandidates.length; i++) {
    if (resGR.isValidField(fieldCandidates[i])) {
      fieldUsed = fieldCandidates[i];
      break;
    }
  }

  if (fieldUsed) {
    resGR[fieldUsed] = aclListStr;
    resGR.update();
    SUMMARY.resourceAcls = 'Resource ACLs set via field "' + fieldUsed + '": ' + aclListStr;
  } else {
    SUMMARY.resourceAcls = 'No ACL field found on resource table.';
    SUMMARY.manualActions.push(
      'Set Resource ACLs manually in UI — none of [enforce_acl, override_acl, acl, default_acl] found on ' +
      resGR.getTableName() + '.'
    );
  }
}

// =================================================================================================
// EXECUTE — Run all steps in sequence
// =================================================================================================

// Step 1: Role
var roleId = getOrCreateRole(ROLE_NAME);

// Step 2: Create/find "Microsoft Copilot" ACL (REST_Endpoint, Execute)
var copilotAcl   = createEndpointExecuteAcl(ACL_NAME);
var copilotAclId = copilotAcl.sys_id.toString();

// Step 3: Link the ACL to the role
linkAclToRole(copilotAclId, roleId);

// Step 4: Find the OOTB "Scripted REST External Default" ACL
var externalDefaultAclId = findExternalDefaultAcl();

// Build the combined ACL list for assignment to both the API and Resource
var aclListStr = buildAclList(copilotAclId, externalDefaultAclId);

// Step 5: Create/find the Scripted REST API
var apiDef = getOrCreateScriptedApi(API_NAME, API_ID_VALUE);

// Step 6: Assign Default ACLs on the API
setApiDefaultAcls(apiDef, aclListStr);

// Step 7: Create/find the Resource
var res = createResourceOrOperation(apiDef, RESOURCE_NAME, RESOURCE_PATH, RESOURCE_SCRIPT);

// Step 8: Assign ACLs on the Resource
setResourceAcls(res, aclListStr);

// =================================================================================================
// SUMMARY — Print results for review
// =================================================================================================

gs.print('\n--- Scripted REST API Setup Summary ---');
gs.print('Role:                 ' + SUMMARY.role);
gs.print('Endpoint ACL:         ' + SUMMARY.endpointAcl);
gs.print('Endpoint ACL → Role:  ' + SUMMARY.endpointAclLinked);
gs.print('External Default ACL: ' + SUMMARY.externalDefaultAcl);
gs.print('ACL list (glide_list):' + aclListStr);
gs.print('API:                  ' + SUMMARY.api);
gs.print('API Default ACLs:     ' + SUMMARY.apiDefaultAcls);
gs.print('Resource:             ' + SUMMARY.resource);
gs.print('Resource ACLs:        ' + SUMMARY.resourceAcls);
if (SUMMARY.manualActions.length) {
  gs.warn('\nManual follow-ups needed:');
  SUMMARY.manualActions.forEach(function(s) { gs.warn('  - ' + s); });
} else {
  gs.print('\nAll steps completed successfully. No manual actions needed.');
}
