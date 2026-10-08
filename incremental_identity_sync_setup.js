// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// =================================================================================================
// ServiceNow Background Script: Set up Incremental Identity Sync for Microsoft 365 Copilot Connector
// =================================================================================================
// PURPOSE
// -------
// This script automates the "Set up REST API for incremental identity sync" steps documented at:
//   https://learn.microsoft.com/en-us/microsoft-365/copilot/connectors/servicenow-knowledge-admin-setup#set-up-rest-api-for-incremental-identity-sync
//
// Incremental identity sync keeps identity changes — new or removed users, role assignments, group
// memberships, and user_criteria definitions — up to date BETWEEN full crawls. It applies only to
// the "Advanced" flow and relies on ServiceNow auditing so the connector can detect changes.
//
// WHAT THIS SCRIPT DOES (in a single run)
// ----------------------------------------
// 1. Adds the "user_changes" resource (GET /user_changes) to the "Microsoft Copilot" Scripted REST
//    API (the same API created by scripted_rest_api_setup.js — it is reused, never duplicated).
// 2. Grants the crawl role row-level READ access to sys_audit and sys_audit_delete.
// 3. Enables auditing on the monitored tables and fields. ServiceNow records field CHANGES only when
//    the TABLE is audited, so the script enables table-level auditing (which also makes deletions
//    land in sys_audit_delete) and sets the field-level audit flag on each documented field.
//
// RUN ORDER (this is the LAST script, run only for Advanced flow + incremental identity sync):
//   federated_auth_setup.js (if Federated Auth)
//     -> row_level_acl_setup.js
//     -> field_level_acl_setup.js (if needed)
//     -> scripted_rest_api_setup.js
//     -> incremental_identity_sync_setup.js   (THIS SCRIPT)
//
// WHAT THIS SCRIPT DOES NOT DO
// -----------------------------
// - It does NOT activate the Audit plugin (com.glide.audit). That plugin is active by default on
//   current releases; the script verifies the audit tables exist and flags a manual step if not.
// - It does NOT create the service account/role (row_level_acl_setup.js does) — it reuses the role.
// - It does NOT delete or modify existing ACLs, resources, or audit config beyond enabling the
//   documented audit flags.
//
// PREREQUISITES
// --------------
// - Elevate to the security_admin role before running (All > Scripts - Background, Global scope).

gs.requireSecurityAdmin();

// =================================================================================================
// CONFIGURATION
// =================================================================================================
// For most deployments the defaults below match the Microsoft Learn documentation exactly.

var ROLE_NAME                 = 'copilot_connector';        // Role granted execute access on the endpoint
                                                            // AND read access to the audit tables. Must be
                                                            // the SAME role the crawl account holds (the one
                                                            // row_level_acl_setup.js created). Set to '' to
                                                            // fall back to the built-in 'admin' role
                                                            // (NOT recommended — the crawl account is not admin).

var ACL_NAME                  = 'Microsoft Copilot';        // REST_Endpoint execute ACL name (per the docs).
var API_NAME                  = 'Microsoft Copilot';        // Display name of the Scripted REST API.
var API_ID_VALUE              = 'microsoft_copilot';        // API ID used in the endpoint URL path:
                                                            // /api/<namespace>/microsoft_copilot/user_changes

var RESOURCE_NAME             = 'user_changes';             // Name of the API resource.
var RESOURCE_PATH             = '/user_changes';            // Relative path appended to the API base path.
var RESOURCE_METHOD           = 'GET';                      // HTTP method the connector uses to call it.

var EXTERNAL_DEFAULT_ACL_NAME = 'Scripted REST External Default';
                                                            // Out-of-the-box ACL from the Scripted REST
                                                            // plugin. Looked up by name — never created here.

// Tables the connector queries directly for change detection — grant row-level READ ACLs on these.
// (sys_user, sys_user_has_role, sys_user_grmember, and user_criteria read access is already granted
//  by row_level_acl_setup.js, so only the audit tables are added here.)
var AUDIT_READ_TABLES = ['sys_audit', 'sys_audit_delete'];

// Tables and the fields to audit, per the "Audited fields" table in the documentation. The script
// enables auditing at the TABLE level (sys_dictionary collection record audit=true) — the only way
// ServiceNow records field CHANGES in sys_audit (and it also makes deletions land in
// sys_audit_delete) — and also sets the field-level audit flag on each listed field.
var AUDIT_FIELDS = {
  'sys_user':          ['active', 'department', 'company', 'location'],
  'sys_user_has_role': ['user'],
  'sys_user_grmember': ['user'],
  'user_criteria':     ['role', 'group', 'company', 'department', 'location', 'script', 'active', 'match_all']
};

var ACL_ORDER = 50;   // Evaluation order for new ACLs (lower = evaluated earlier).

// Marker written into the audit-table ACL description for idempotent re-identification on re-runs.
var MARKER = 'AUTO-ACL for role=' + ROLE_NAME + ' (KB-connector identity-sync)';

// The script the "user_changes" resource executes. Detects identity-relevant changes since a given
// timestamp via sys_audit / sys_audit_delete. This is the exact script from the Microsoft Learn
// documentation referenced above.
var RESOURCE_SCRIPT = [
  "(function process(/*RESTAPIRequest*/ request, /*RESTAPIResponse*/ response) {",
  "",
  "    var since = String(request.queryParams.since).trim();",
  "    var checkpoint = request.queryParams.checkpoint",
  "        ? String(request.queryParams.checkpoint)",
  "        : 'all';",
  "",
  "    // Validate required parameter",
  "    if (!since || since === 'undefined' || since === 'null') {",
  "        response.setStatus(400);",
  "        response.setBody({ error: 'Missing required query parameter: since' });",
  "        return;",
  "    }",
  "",
  "    // Map<key, {id, type, action, timestamp}>  key = type + ':' + id for dedup",
  "    var changesMap = {};",
  "",
  "    function addChange(id, type, action, timestamp) {",
  "        if (!id) {",
  "            return;",
  "        }",
  "        var key = type + ':' + id;",
  "        if (!changesMap[key]) {",
  "            changesMap[key] = { id: id, type: type, action: action, timestamp: timestamp };",
  "        } else {",
  "            // Priority: deleted > added > modified",
  "            var existing = changesMap[key];",
  "            if (action === 'deleted') {",
  "                existing.action = 'deleted';",
  "            } else if (action === 'added' && existing.action !== 'deleted') {",
  "                existing.action = 'added';",
  "            }",
  "            // Keep latest timestamp",
  "            if (timestamp > existing.timestamp) {",
  "                existing.timestamp = timestamp;",
  "            }",
  "        }",
  "    }",
  "",
  "    // =======================================================================",
  "    // Checkpoint: sys_user_fields",
  "    // Queries sys_audit for identity-relevant field changes on sys_user.",
  "    // Requires auditing enabled on: department, company, location, active",
  "    // =======================================================================",
  "    if (checkpoint === 'all' || checkpoint === 'sys_user_fields') {",
  "        var identityFields = 'active,department,company,location';",
  "",
  "        var auditGr = new GlideRecord('sys_audit');",
  "        auditGr.addQuery('tablename', 'sys_user');",
  "        auditGr.addQuery('sys_created_on', '>=', since);",
  "        auditGr.addQuery('fieldname', 'IN', identityFields);",
  "        auditGr.orderBy('sys_created_on');",
  "        auditGr.query();",
  "",
  "        while (auditGr.next()) {",
  "            var docId = auditGr.getValue('documentkey');",
  "            var auditTs = auditGr.getValue('sys_created_on');",
  "            var auditType = auditGr.getValue('type');",
  "            var action = (auditType === 'INSERT') ? 'added' : 'modified';",
  "            addChange(docId, 'user', action, auditTs);",
  "        }",
  "    }",
  "",
  "    // =======================================================================",
  "    // Checkpoint: sys_user_has_role",
  "    // Direct table query for role assignment additions/modifications.",
  "    // =======================================================================",
  "    if (checkpoint === 'all' || checkpoint === 'sys_user_has_role') {",
  "        var roleGr = new GlideRecord('sys_user_has_role');",
  "        roleGr.addQuery('sys_updated_on', '>=', since);",
  "        roleGr.query();",
  "",
  "        while (roleGr.next()) {",
  "            var roleUserId = roleGr.getValue('user');",
  "            var roleTs = roleGr.getValue('sys_updated_on');",
  "            addChange(roleUserId, 'user', 'modified', roleTs);",
  "        }",
  "    }",
  "",
  "    // =======================================================================",
  "    // Checkpoint: sys_user_has_role_deleted",
  "    // Detects deleted role assignments via sys_audit_delete, then resolves",
  "    // the affected user by looking up the sys_audit INSERT record for the",
  "    // deleted M2M record's 'user' field.",
  "    // =======================================================================",
  "    if (checkpoint === 'all' || checkpoint === 'sys_user_has_role_deleted') {",
  "        var deletedRoleKeys = [];",
  "        var deletedRoleTimestamps = {};",
  "",
  "        var delRoleGr = new GlideRecord('sys_audit_delete');",
  "        delRoleGr.addQuery('tablename', 'sys_user_has_role');",
  "        delRoleGr.addQuery('sys_created_on', '>=', since);",
  "        delRoleGr.query();",
  "",
  "        while (delRoleGr.next()) {",
  "            var delRoleDocKey = delRoleGr.getValue('documentkey');",
  "            var delRoleTs = delRoleGr.getValue('sys_created_on');",
  "            deletedRoleKeys.push(delRoleDocKey);",
  "            deletedRoleTimestamps[delRoleDocKey] = delRoleTs;",
  "        }",
  "",
  "        // Resolve which user each deleted role assignment belonged to",
  "        if (deletedRoleKeys.length > 0) {",
  "            var roleAuditGr = new GlideRecord('sys_audit');",
  "            roleAuditGr.addQuery('tablename', 'sys_user_has_role');",
  "            roleAuditGr.addQuery('documentkey', 'IN', deletedRoleKeys.join(','));",
  "            roleAuditGr.addQuery('fieldname', 'user');",
  "            roleAuditGr.addQuery('type', 'INSERT');",
  "            roleAuditGr.query();",
  "",
  "            while (roleAuditGr.next()) {",
  "                var roleDocKey = roleAuditGr.getValue('documentkey');",
  "                var roleUserVal = roleAuditGr.getValue('newvalue');",
  "                if (roleUserVal && deletedRoleTimestamps[roleDocKey]) {",
  "                    addChange(roleUserVal, 'user', 'modified', deletedRoleTimestamps[roleDocKey]);",
  "                }",
  "            }",
  "        }",
  "    }",
  "",
  "    // =======================================================================",
  "    // Checkpoint: sys_user_grmember",
  "    // Direct table query for group membership additions/modifications.",
  "    // =======================================================================",
  "    if (checkpoint === 'all' || checkpoint === 'sys_user_grmember') {",
  "        var groupGr = new GlideRecord('sys_user_grmember');",
  "        groupGr.addQuery('sys_updated_on', '>=', since);",
  "        groupGr.query();",
  "",
  "        while (groupGr.next()) {",
  "            var groupUserId = groupGr.getValue('user');",
  "            var groupTs = groupGr.getValue('sys_updated_on');",
  "            addChange(groupUserId, 'user', 'modified', groupTs);",
  "        }",
  "    }",
  "",
  "    // =======================================================================",
  "    // Checkpoint: sys_user_grmember_deleted",
  "    // Detects deleted group memberships via sys_audit_delete, then resolves",
  "    // the affected user by looking up the sys_audit INSERT record for the",
  "    // deleted M2M record's 'user' field.",
  "    // =======================================================================",
  "    if (checkpoint === 'all' || checkpoint === 'sys_user_grmember_deleted') {",
  "        var deletedGrpKeys = [];",
  "        var deletedGrpTimestamps = {};",
  "",
  "        var delGrpGr = new GlideRecord('sys_audit_delete');",
  "        delGrpGr.addQuery('tablename', 'sys_user_grmember');",
  "        delGrpGr.addQuery('sys_created_on', '>=', since);",
  "        delGrpGr.query();",
  "",
  "        while (delGrpGr.next()) {",
  "            var delGrpDocKey = delGrpGr.getValue('documentkey');",
  "            var delGrpTs = delGrpGr.getValue('sys_created_on');",
  "            deletedGrpKeys.push(delGrpDocKey);",
  "            deletedGrpTimestamps[delGrpDocKey] = delGrpTs;",
  "        }",
  "",
  "        // Resolve which user each deleted group membership belonged to",
  "        if (deletedGrpKeys.length > 0) {",
  "            var grpAuditGr = new GlideRecord('sys_audit');",
  "            grpAuditGr.addQuery('tablename', 'sys_user_grmember');",
  "            grpAuditGr.addQuery('documentkey', 'IN', deletedGrpKeys.join(','));",
  "            grpAuditGr.addQuery('fieldname', 'user');",
  "            grpAuditGr.addQuery('type', 'INSERT');",
  "            grpAuditGr.query();",
  "",
  "            while (grpAuditGr.next()) {",
  "                var grpDocKey = grpAuditGr.getValue('documentkey');",
  "                var grpUserVal = grpAuditGr.getValue('newvalue');",
  "                if (grpUserVal && deletedGrpTimestamps[grpDocKey]) {",
  "                    addChange(grpUserVal, 'user', 'modified', deletedGrpTimestamps[grpDocKey]);",
  "                }",
  "            }",
  "        }",
  "    }",
  "",
  "    // =======================================================================",
  "    // Checkpoint: sys_user_deactivated",
  "    // Detects recently deactivated users. Treated as deleted since the user",
  "    // should be removed from the identity set.",
  "    // =======================================================================",
  "    if (checkpoint === 'all' || checkpoint === 'sys_user_deactivated') {",
  "        var deactivatedGr = new GlideRecord('sys_user');",
  "        deactivatedGr.addQuery('active', false);",
  "        deactivatedGr.addQuery('sys_updated_on', '>=', since);",
  "        deactivatedGr.query();",
  "",
  "        while (deactivatedGr.next()) {",
  "            var deactivatedId = deactivatedGr.getUniqueValue();",
  "            var deactivateTs = deactivatedGr.getValue('sys_updated_on');",
  "            addChange(deactivatedId, 'user', 'deleted', deactivateTs);",
  "        }",
  "    }",
  "",
  "    // =======================================================================",
  "    // Checkpoint: sys_audit_delete_user",
  "    // Detects hard-deleted users via sys_audit_delete.",
  "    // =======================================================================",
  "    if (checkpoint === 'all' || checkpoint === 'sys_audit_delete_user') {",
  "        var deleteGr = new GlideRecord('sys_audit_delete');",
  "        deleteGr.addQuery('tablename', 'sys_user');",
  "        deleteGr.addQuery('sys_created_on', '>=', since);",
  "        deleteGr.query();",
  "",
  "        while (deleteGr.next()) {",
  "            var deletedDocId = deleteGr.getValue('documentkey');",
  "            var deleteTimestamp = deleteGr.getValue('sys_created_on');",
  "            addChange(deletedDocId, 'user', 'deleted', deleteTimestamp);",
  "        }",
  "    }",
  "",
  "    // =======================================================================",
  "    // Checkpoint: user_criteria",
  "    // Detects changes to user_criteria definitions via sys_audit.",
  "    // When a user_criteria changes, all users evaluated against that criteria",
  "    // may have different access - the connector must re-evaluate.",
  "    //",
  "    // Monitored fields: role, group, company, department, location,",
  "    //                   script, active, match_all",
  "    // =======================================================================",
  "    if (checkpoint === 'all' || checkpoint === 'user_criteria') {",
  "        var ucFields = 'role,group,company,department,location,script,active,match_all';",
  "",
  "        var ucAuditGr = new GlideRecord('sys_audit');",
  "        ucAuditGr.addQuery('tablename', 'user_criteria');",
  "        ucAuditGr.addQuery('sys_created_on', '>=', since);",
  "        ucAuditGr.addQuery('fieldname', 'IN', ucFields);",
  "        ucAuditGr.orderBy('sys_created_on');",
  "        ucAuditGr.query();",
  "",
  "        while (ucAuditGr.next()) {",
  "            var ucDocId = ucAuditGr.getValue('documentkey');",
  "            var ucTs = ucAuditGr.getValue('sys_created_on');",
  "            var ucType = ucAuditGr.getValue('type');",
  "            var ucAction = (ucType === 'INSERT') ? 'added' : 'modified';",
  "            addChange(ucDocId, 'user_criteria', ucAction, ucTs);",
  "        }",
  "",
  "        // Also detect deleted user_criteria via sys_audit_delete",
  "        var ucDeleteGr = new GlideRecord('sys_audit_delete');",
  "        ucDeleteGr.addQuery('tablename', 'user_criteria');",
  "        ucDeleteGr.addQuery('sys_created_on', '>=', since);",
  "        ucDeleteGr.query();",
  "",
  "        while (ucDeleteGr.next()) {",
  "            var ucDeletedId = ucDeleteGr.getValue('documentkey');",
  "            var ucDeleteTs = ucDeleteGr.getValue('sys_created_on');",
  "            addChange(ucDeletedId, 'user_criteria', 'deleted', ucDeleteTs);",
  "        }",
  "    }",
  "",
  "    // =======================================================================",
  "    // Build and return response",
  "    // =======================================================================",
  "    var keys = Object.keys(changesMap);",
  "    var changes = [];",
  "",
  "    for (var i = 0; i < keys.length; i++) {",
  "        changes.push(changesMap[keys[i]]);",
  "    }",
  "",
  "    response.setBody([{",
  "        changes: changes,",
  "        totalCount: changes.length,",
  "        checkpoint: checkpoint,",
  "        since: since",
  "    }]);",
  "",
  "})(request, response);"
].join("\n");

// =================================================================================================
// INTERNAL: Summary tracker
// =================================================================================================

var SUMMARY = {
  role: '', endpointAcl: '', endpointAclLinked: '', externalDefaultAcl: '',
  api: '', apiDefaultAcls: '', resource: '', resourceAcls: '',
  auditReadAcls: [], tableAudit: [], fieldAudit: [], auditInfra: '',
  manualActions: []
};

// =================================================================================================
// UTILITY
// =================================================================================================

function tableExists(tbl) {
  try { var gr = new GlideRecord(tbl); return gr.isValid(); } catch (e) { return false; }
}

function boolTrue(v) { return v == '1' || v == 'true'; }

// =================================================================================================
// STEP 1: ROLE — locate or create the role used for ACL authorization
// =================================================================================================

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
    SUMMARY.role = 'Role reused: ' + name + ' (' + r.sys_id + ')';
    return r.sys_id.toString();
  }
  r.initialize();
  r.name = name;
  r.description = name + ' (auto-created for Copilot connector)';
  var id = r.insert();
  if (!id) throw 'Failed to create role: ' + name;
  SUMMARY.role = 'Role created: ' + name + ' (' + id + ')';
  return id;
}

// =================================================================================================
// STEP 2: ENDPOINT ACL — reuse or create the "Microsoft Copilot" REST_Endpoint execute ACL
// =================================================================================================

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
  var existing = findAcl('REST_Endpoint', 'execute', nameValue);
  if (existing) {
    SUMMARY.endpointAcl = 'Endpoint ACL reused: ' + nameValue + ' (' + existing.sys_id + ')';
    return existing;
  }
  var a = new GlideRecord('sys_security_acl');
  a.initialize();
  a.type            = 'REST_Endpoint';
  a.operation       = 'execute';
  a.name            = nameValue;
  a.active          = true;
  a.admin_overrides = true;
  if (a.isValidField('order')) a.order = ACL_ORDER;
  a.script          = '';
  a.description     = 'REST_Endpoint Execute ACL for ' + nameValue;
  var id = a.insert();
  if (!id) throw 'Failed to insert endpoint ACL: ' + nameValue;
  a.get(id);
  SUMMARY.endpointAcl = 'Endpoint ACL created: ' + nameValue + ' (' + id + ')';
  return a;
}

// =================================================================================================
// STEP 3: LINK ACL TO ROLE (sys_security_acl_role M2M)
// =================================================================================================

function linkAclToRole(aclId, roleId) {
  var m = new GlideRecord('sys_security_acl_role');
  m.addQuery('sys_security_acl', aclId);
  m.addQuery('sys_user_role', roleId);
  m.query();
  if (m.next()) return;
  m.initialize();
  m.sys_security_acl = aclId;
  m.sys_user_role    = roleId;
  if (!m.insert()) throw 'Failed to link ACL to role';
}

// =================================================================================================
// STEP 4: FIND the out-of-the-box "Scripted REST External Default" ACL
// =================================================================================================

function findExternalDefaultAcl() {
  var acl = findAclByName(EXTERNAL_DEFAULT_ACL_NAME);
  if (acl) {
    SUMMARY.externalDefaultAcl = 'External Default ACL found: ' + EXTERNAL_DEFAULT_ACL_NAME + ' (' + acl.sys_id + ')';
    return acl.sys_id.toString();
  }
  acl = findAclByName(EXTERNAL_DEFAULT_ACL_NAME + ' ACL');
  if (acl) {
    SUMMARY.externalDefaultAcl = 'External Default ACL found (alt name): ' + acl.name + ' (' + acl.sys_id + ')';
    return acl.sys_id.toString();
  }
  var a = new GlideRecord('sys_security_acl');
  a.addQuery('name', 'CONTAINS', 'Scripted REST External Default');
  a.query();
  if (a.next()) {
    SUMMARY.externalDefaultAcl = 'External Default ACL found (partial): ' + a.name + ' (' + a.sys_id + ')';
    return a.sys_id.toString();
  }
  SUMMARY.externalDefaultAcl = 'NOT FOUND — will only assign Microsoft Copilot ACL';
  SUMMARY.manualActions.push('OOTB ACL "' + EXTERNAL_DEFAULT_ACL_NAME + '" not found. Add it manually to the API and resource ACLs.');
  return null;
}

function buildAclList(copilotAclId, externalDefaultAclId) {
  if (copilotAclId && externalDefaultAclId) return copilotAclId + ',' + externalDefaultAclId;
  if (copilotAclId) return copilotAclId;
  if (externalDefaultAclId) return externalDefaultAclId;
  return '';
}

// =================================================================================================
// STEP 5: REUSE the Scripted REST API definition (created by scripted_rest_api_setup.js)
// =================================================================================================
// Idempotent: reuses the oldest "Microsoft Copilot" API if present; otherwise creates it so this
// script can also run standalone. Duplicates and API-ID drift are flagged, not auto-changed.

function getOrCreateScriptedApi(apiName, apiIdValue) {
  var matches = [];
  var probe = new GlideRecord('sys_ws_definition');
  probe.addQuery('name', apiName);
  probe.orderBy('sys_created_on');
  probe.query();
  while (probe.next()) matches.push(probe.sys_id.toString());

  if (matches.length) {
    var d = new GlideRecord('sys_ws_definition');
    d.get(matches[0]);
    if (matches.length > 1) {
      SUMMARY.manualActions.push('Found ' + matches.length + ' Scripted REST APIs named "' + apiName +
        '". Reusing the oldest (' + matches[0] + '). Review/delete duplicate(s): ' + matches.slice(1).join(', '));
    }
    var idField = d.isValidField('service_id') ? 'service_id' : (d.isValidField('api_id') ? 'api_id' : null);
    if (idField && d.getValue(idField) !== apiIdValue) {
      SUMMARY.manualActions.push('API "' + apiName + '" has ' + idField + ' = "' + d.getValue(idField) +
        '" but expected "' + apiIdValue + '". Verify the endpoint URL manually (not auto-changed).');
    }
    SUMMARY.api = 'API reused: ' + apiName + ' (' + d.sys_id + ')';
    return d;
  }

  var n = new GlideRecord('sys_ws_definition');
  n.initialize();
  n.name = apiName;
  n.active = true;
  if (n.isValidField('service_id'))     n.service_id = apiIdValue;
  else if (n.isValidField('api_id'))    n.api_id = apiIdValue;
  else if (n.isValidField('base_uri'))  n.base_uri = '/' + apiIdValue;
  else if (n.isValidField('base_path')) n.base_path = '/' + apiIdValue;
  else SUMMARY.manualActions.push('Set API identifier manually in UI for "' + apiName + '".');
  if (n.isValidField('requires_authentication')) n.requires_authentication = true;
  var id = n.insert();
  if (!id) throw 'Failed to create Scripted REST API: ' + apiName;
  n.get(id);
  SUMMARY.api = 'API created: ' + apiName + ' (' + id + ')';
  return n;
}

// =================================================================================================
// STEP 6: ASSIGN Default ACLs on the API
// =================================================================================================

function setApiDefaultAcls(defGR, aclListStr) {
  if (!aclListStr) {
    SUMMARY.apiDefaultAcls = 'No ACLs to assign (lookups failed).';
    SUMMARY.manualActions.push('Set API Default ACLs manually in UI.');
    return;
  }
  var fieldCandidates = ['enforce_acl', 'default_acl'];
  var fieldUsed = null;
  for (var i = 0; i < fieldCandidates.length; i++) {
    if (defGR.isValidField(fieldCandidates[i])) { fieldUsed = fieldCandidates[i]; break; }
  }
  if (fieldUsed) {
    defGR[fieldUsed] = aclListStr;
    defGR.update();
    SUMMARY.apiDefaultAcls = 'API Default ACLs set via "' + fieldUsed + '": ' + aclListStr;
  } else {
    SUMMARY.apiDefaultAcls = 'No ACL field found on sys_ws_definition.';
    SUMMARY.manualActions.push('Set API Default ACLs manually in UI.');
  }
}

// =================================================================================================
// STEP 7: CREATE or UPDATE the "user_changes" resource (GET /user_changes)
// =================================================================================================
// Idempotent: an existing resource of the same name under this API is updated in place (script and
// settings self-heal), never duplicated. Stored in sys_ws_resource or sys_ws_operation by version.

function createResourceOrOperation(defGR, resName, relPath, httpMethod, scriptBody) {
  var useRes = tableExists('sys_ws_resource');
  var useOp  = tableExists('sys_ws_operation');
  if (!useRes && !useOp) {
    SUMMARY.manualActions.push('Create resource via UI (no sys_ws_resource/operation table).');
    return null;
  }
  var tbl = useRes ? 'sys_ws_resource' : 'sys_ws_operation';

  function scriptFieldOf(gr) {
    if (gr.isValidField('operation_script')) return 'operation_script';
    if (gr.isValidField('script'))           return 'script';
    return null;
  }

  var r = new GlideRecord(tbl);
  r.addQuery('web_service_definition', defGR.sys_id);
  if (r.isValidField('name')) r.addQuery('name', resName);
  r.orderBy('sys_created_on');
  r.query();

  if (r.next()) {
    var changes = [];
    var sf = scriptFieldOf(r);
    if (sf) {
      var currentScript = (r.getValue(sf) || '').replace(/\r\n/g, '\n');
      if (currentScript !== scriptBody) { r.setValue(sf, scriptBody); changes.push('script'); }
    } else {
      SUMMARY.manualActions.push('Paste resource script in UI (script field not accessible).');
    }
    if (r.isValidField('relative_path')) {
      if (r.getValue('relative_path') !== relPath) { r.relative_path = relPath; changes.push('relative_path'); }
    } else if (r.isValidField('http_path')) {
      if (r.getValue('http_path') !== relPath) { r.http_path = relPath; changes.push('http_path'); }
    }
    if (r.isValidField('http_method') && r.getValue('http_method') !== httpMethod) { r.http_method = httpMethod; changes.push('http_method'); }
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
    var dupCount = 0;
    var dup = new GlideRecord(tbl);
    dup.addQuery('web_service_definition', defGR.sys_id);
    if (dup.isValidField('name')) dup.addQuery('name', resName);
    dup.addQuery('sys_id', '!=', r.sys_id.toString());
    dup.query();
    while (dup.next()) dupCount++;
    if (dupCount) {
      SUMMARY.manualActions.push('Found ' + (dupCount + 1) + ' "' + resName + '" resources under this API. Updated one; review/delete the ' + dupCount + ' duplicate(s).');
    }
    return r;
  }

  r = new GlideRecord(tbl);
  r.initialize();
  if (r.isValidField('web_service_definition')) r.web_service_definition = defGR.sys_id;
  if (r.isValidField('name'))           r.name = resName;
  if (r.isValidField('relative_path'))  r.relative_path = relPath;
  else if (r.isValidField('http_path')) r.http_path = relPath;
  r.active = true;
  if (r.isValidField('http_method')) r.http_method = httpMethod;
  if (r.isValidField('requires_authentication'))    r.requires_authentication    = true;
  if (r.isValidField('requires_acl_authorization')) r.requires_acl_authorization = true;
  if (r.isValidField('requires_acl'))               r.requires_acl               = true;
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
// STEP 8: ASSIGN ACLs on the resource
// =================================================================================================

function setResourceAcls(resGR, aclListStr) {
  if (!resGR || !aclListStr) { SUMMARY.resourceAcls = 'No resource or no ACLs to assign.'; return; }
  var fieldCandidates = ['enforce_acl', 'override_acl', 'acl', 'default_acl'];
  var fieldUsed = null;
  for (var i = 0; i < fieldCandidates.length; i++) {
    if (resGR.isValidField(fieldCandidates[i])) { fieldUsed = fieldCandidates[i]; break; }
  }
  if (fieldUsed) {
    resGR[fieldUsed] = aclListStr;
    resGR.update();
    SUMMARY.resourceAcls = 'Resource ACLs set via "' + fieldUsed + '": ' + aclListStr;
  } else {
    SUMMARY.resourceAcls = 'No ACL field found on resource table.';
    SUMMARY.manualActions.push('Set Resource ACLs manually in UI.');
  }
}

// =================================================================================================
// STEP 9: ROW-LEVEL READ ACLs for the audit tables (sys_audit, sys_audit_delete)
// =================================================================================================
// Same record-level READ ACL pattern used by row_level_acl_setup.js, linked to the crawl role.

function ensureRowReadAcl(table, roleId) {
  if (!tableExists(table)) {
    SUMMARY.auditReadAcls.push(table + ': SKIPPED (table not present)');
    return;
  }
  // Idempotency: reuse any record-level READ ACL for this table that is already linked to our role.
  // We match on role linkage rather than a description marker because ServiceNow's ACLDescriber
  // business rule rewrites the ACL description after the role is linked (which defeats a marker).
  var acl = new GlideRecord('sys_security_acl');
  acl.addQuery('type', 'record');
  acl.addQuery('operation', 'read');
  acl.addQuery('name', table);
  acl.query();
  while (acl.next()) {
    var link = new GlideRecord('sys_security_acl_role');
    link.addQuery('sys_security_acl', acl.sys_id.toString());
    link.addQuery('sys_user_role', roleId);
    link.setLimit(1);
    link.query();
    if (link.next()) {
      SUMMARY.auditReadAcls.push(table + ': ACL reused (' + acl.sys_id + ')');
      return;
    }
  }
  // None linked to our role yet — create a new record-level READ ACL and link it.
  var a = new GlideRecord('sys_security_acl');
  a.initialize();
  a.type            = 'record';
  a.name            = table;
  a.operation       = 'read';
  a.active          = true;
  a.admin_overrides = true;
  if (a.isValidField('order')) a.order = ACL_ORDER;
  a.script          = '';
  if (a.isValidField('description')) a.description = MARKER + ' | table=' + table;
  var aclId = a.insert();
  if (!aclId) { SUMMARY.auditReadAcls.push(table + ': FAILED to create ACL'); return; }
  linkAclToRole(aclId, roleId);
  SUMMARY.auditReadAcls.push(table + ': ACL created (' + aclId + ')');
}

// =================================================================================================
// STEP 10: ENABLE AUDITING on the monitored tables and fields
// =================================================================================================
// ServiceNow records field CHANGES in sys_audit only when the TABLE is audited (the sys_dictionary
// collection record has audit=true); a field-level audit flag by itself does not capture changes.
// So the script enables TABLE-level auditing on each table (which audits the listed fields' changes
// and makes deletions land in sys_audit_delete) AND sets the field-level audit flag on each listed
// field to match the documented "Audited fields".

// Enable auditing at the table (collection) level: the sys_dictionary record with an empty element.
function enableTableAudit(table) {
  var d = new GlideRecord('sys_dictionary');
  d.addQuery('name', table);
  d.addNullQuery('element');
  d.setLimit(1);
  d.query();
  if (!d.next()) {
    SUMMARY.tableAudit.push(table + ': collection dictionary record NOT FOUND');
    SUMMARY.manualActions.push('Enable table auditing manually on ' + table + ' (collection dictionary record not found).');
    return;
  }
  if (boolTrue(d.getValue('audit'))) {
    SUMMARY.tableAudit.push(table + ': already audited');
    return;
  }
  d.setValue('audit', true);
  if (d.update()) SUMMARY.tableAudit.push(table + ': table auditing enabled');
  else SUMMARY.tableAudit.push(table + ': FAILED to enable table auditing');
}

function enableFieldAudit(table, field) {
  var d = new GlideRecord('sys_dictionary');
  d.addQuery('name', table);
  d.addQuery('element', field);
  d.setLimit(1);
  d.query();
  if (!d.next()) {
    SUMMARY.fieldAudit.push(table + '.' + field + ': NOT FOUND');
    SUMMARY.manualActions.push('Enable auditing manually on ' + table + '.' + field + ' (dictionary record not found).');
    return;
  }
  if (boolTrue(d.getValue('audit'))) {
    SUMMARY.fieldAudit.push(table + '.' + field + ': already audited');
    return;
  }
  d.setValue('audit', true);
  if (d.update()) SUMMARY.fieldAudit.push(table + '.' + field + ': auditing enabled');
  else SUMMARY.fieldAudit.push(table + '.' + field + ': FAILED to enable');
}

// =================================================================================================
// EXECUTE
// =================================================================================================

var roleId = getOrCreateRole(ROLE_NAME);

var copilotAcl   = createEndpointExecuteAcl(ACL_NAME);
var copilotAclId = copilotAcl.sys_id.toString();
linkAclToRole(copilotAclId, roleId);
SUMMARY.endpointAclLinked = 'Endpoint ACL linked to role';

var externalDefaultAclId = findExternalDefaultAcl();
var aclListStr = buildAclList(copilotAclId, externalDefaultAclId);

var apiDef = getOrCreateScriptedApi(API_NAME, API_ID_VALUE);
setApiDefaultAcls(apiDef, aclListStr);

var res = createResourceOrOperation(apiDef, RESOURCE_NAME, RESOURCE_PATH, RESOURCE_METHOD, RESOURCE_SCRIPT);
setResourceAcls(res, aclListStr);

// Audit-table read ACLs
for (var t = 0; t < AUDIT_READ_TABLES.length; t++) ensureRowReadAcl(AUDIT_READ_TABLES[t], roleId);

// Enable auditing on each table (table-level — captures changes + deletes) and on each listed field
for (var tbl in AUDIT_FIELDS) {
  if (!AUDIT_FIELDS.hasOwnProperty(tbl)) continue;
  if (!tableExists(tbl)) { SUMMARY.tableAudit.push(tbl + ': SKIPPED (table not present)'); continue; }
  enableTableAudit(tbl);
  var flds = AUDIT_FIELDS[tbl];
  for (var f = 0; f < flds.length; f++) enableFieldAudit(tbl, flds[f]);
}

// Audit infrastructure check (the Audit plugin must be active for sys_audit/sys_audit_delete to fill)
if (tableExists('sys_audit') && tableExists('sys_audit_delete')) {
  SUMMARY.auditInfra = 'sys_audit and sys_audit_delete are present (Audit plugin active).';
} else {
  SUMMARY.auditInfra = 'Audit tables missing — activate the Audit plugin (com.glide.audit).';
  SUMMARY.manualActions.push('Activate the Audit plugin (com.glide.audit); sys_audit/sys_audit_delete not found.');
}

// =================================================================================================
// SUMMARY
// =================================================================================================

gs.print('\n--- Incremental Identity Sync Setup Summary ---');
gs.print('Role:                 ' + SUMMARY.role);
gs.print('Endpoint ACL:         ' + SUMMARY.endpointAcl);
gs.print('Endpoint ACL -> Role: ' + SUMMARY.endpointAclLinked);
gs.print('External Default ACL: ' + SUMMARY.externalDefaultAcl);
gs.print('ACL list (glide_list):' + aclListStr);
gs.print('API:                  ' + SUMMARY.api);
gs.print('API Default ACLs:     ' + SUMMARY.apiDefaultAcls);
gs.print('Resource:             ' + SUMMARY.resource);
gs.print('Resource ACLs:        ' + SUMMARY.resourceAcls);
gs.print('Audit read ACLs:');
SUMMARY.auditReadAcls.forEach(function(s) { gs.print('  - ' + s); });
gs.print('Table auditing:');
SUMMARY.tableAudit.forEach(function(s) { gs.print('  - ' + s); });
gs.print('Field auditing:');
SUMMARY.fieldAudit.forEach(function(s) { gs.print('  - ' + s); });
gs.print('Audit infrastructure: ' + SUMMARY.auditInfra);
if (SUMMARY.manualActions.length) {
  gs.warn('\nManual follow-ups needed:');
  SUMMARY.manualActions.forEach(function(s) { gs.warn('  - ' + s); });
} else {
  gs.print('\nAll steps completed successfully. No manual actions needed.');
}
