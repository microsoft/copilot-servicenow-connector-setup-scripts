// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// =================================================================================================
// ServiceNow Background Script: Grant field-level read access to the connector service account
// =================================================================================================
//
// PURPOSE
// -------
// This script automates the "Grant field-level access" steps documented at:
//   https://learn.microsoft.com/en-us/microsoft-365/copilot/connectors/granting-table-access-servicenow-knowledge#grant-field-level-access
//
// After running the row-level ACL setup script, the service account can see rows in each table.
// However, on some instances the field values within those rows may still be hidden due to
// field-level ACL restrictions. This script grants read access to ALL fields (using the `*`
// wildcard) on the tables where field-level access is needed.
//
// WHEN TO USE THIS SCRIPT
// ------------------------
// Run this script ONLY if you have already granted row-level access (either manually or via the
// row-level setup script) and the service account can see rows but NOT field values.
//
// To check: query a table as the service account via the REST API (the machine-identity account
// cannot be impersonated in the UI on Zurich and later), e.g.
// GET https://<instance>.service-now.com/api/now/table/kb_knowledge?sysparm_limit=1 — and verify
// that both rows AND field values are returned. If rows are returned but fields are empty, run this
// script.
// =================================================================================================

gs.requireSecurityAdmin();

// =================================================================================================
// CONFIGURATION
// =================================================================================================
// Edit these values to match your deployment.

var TARGET_ROLE_NAME = 'copilot_connector';    // Name of the role to link field-level ACLs to.
                                                // This must match the role created by the
                                                // row-level setup script (or created manually).

// =================================================================================================
// CONFIGURATION: Tables requiring field-level READ access
// =================================================================================================
// These are the tables where field values may not be visible even after row-level access is
// granted. A field-level READ ACL (table.*) is created for each table listed below.
//
// You can add or remove tables based on your verification results. After running the row-level
// script, query each table as the service account via the REST API — only add tables here where
// field values are hidden.

var TABLES = [
  'kb_knowledge',                  // Knowledge article fields
  'kb_knowledge_base',             // Knowledge base fields
  'sys_user',                      // User record fields
  'sys_user_group',                // User group fields
  'sys_dictionary',                // Dictionary/schema fields
  'sys_attachment',                // Attachment fields
  'sys_properties',                // System property fields (name/value) — required for
                                   // hierarchical permission evaluation. The connector reads
                                   // glide.knowman.apply_article_read_criteria and
                                   // glide.knowman.block_access_with_no_user_criteria. This grants
                                   // field access to ALL sys_properties fields; if you need to
                                   // restrict to just these two properties, use the granular
                                   // per-property ACLs described in the "Set up hierarchical
                                   // permissions" section of the Learn docs instead.
  'kb_knowledge_block',            // Knowledge block fields
  'm2m_kb_knowledge_to_block',     // Article-to-block M2M mapping fields
  'core_company'                   // Company record fields
];

// =================================================================================================
// CONFIGURATION: ACL settings
// =================================================================================================

var ACL_ORDER    = 50;             // Evaluation order for new ACLs (lower = evaluated earlier).

var FORCE_INSERT = false;          // If true, always create a new ACL even when a marker-tagged
                                   // ACL already exists. Not recommended.

// =================================================================================================
// INTERNAL: Derived constants and summary tracker
// =================================================================================================

// Marker written into the ACL description field for idempotency.
// On re-runs the script searches for this marker to identify ACLs it previously created.
var MARKER = 'AUTO-FIELD-ACL for role=' + TARGET_ROLE_NAME + ' (KB-connector)';

var SUMMARY = {
  role: '',
  aclsCreated: [],
  aclsReused: [],
  tablesSkipped: [],
  errors: []
};

// =================================================================================================
// UTILITY FUNCTIONS
// =================================================================================================

// Checks whether a table exists on this instance by querying the sys_db_object dictionary.
function tableExistsOnInstance(tableName) {
  var gr = new GlideRecord('sys_db_object');
  gr.addQuery('name', tableName);
  gr.setLimit(1);
  gr.query();
  return gr.next();
}

// =================================================================================================
// STEP 1: ROLE — Look up the existing role
// =================================================================================================
// The role must already exist (created by the row-level setup script or manually).
// If the role is not found, the script stops immediately — there is no point creating ACLs
// without a role to link them to.

function findRoleId(roleName) {
  var r = new GlideRecord('sys_user_role');
  r.addQuery('name', roleName);
  r.setLimit(1);
  r.query();
  if (r.next()) {
    SUMMARY.role = 'Role found: ' + roleName + ' (' + r.getUniqueValue() + ')';
    return r.getUniqueValue();
  }
  return null;
}

// =================================================================================================
// STEP 2: CREATE FIELD-LEVEL READ ACLs — Grant all-field read access for each table
// =================================================================================================
// For each table in the TABLES array, this step:
//   1. Checks if the table exists on this instance (skips if not).
//   2. Checks if a field-level ACL tagged with our marker already exists (reuses if so).
//   3. Creates a new field-level READ ACL (table.*) if needed.
//   4. Links the custom role to the ACL via sys_security_acl_role.
//
// The ACL name format is "<table_name>.*" — the wildcard `*` applies access to all fields
// in the table. This is the same as selecting the table name in the ACL form and entering
// `*` in the adjacent field name selector.

function ourFieldAclAlreadyExists(table) {
  var a = new GlideRecord('sys_security_acl');
  a.addQuery('type', 'record');
  a.addQuery('operation', 'read');
  a.addQuery('name', table + '.*');
  a.addQuery('description', 'CONTAINS', MARKER);
  a.setLimit(1);
  a.query();
  return a.next() ? a.getUniqueValue() : null;
}

function insertFieldAcl(table) {
  var aclName = table + '.*';
  var a = new GlideRecord('sys_security_acl');
  a.initialize();
  a.type            = 'record';
  a.operation       = 'read';
  a.name            = aclName;
  a.active          = true;
  a.admin_overrides = true;
  if (a.isValidField('order')) a.order = ACL_ORDER;
  a.script          = '';
  if (a.isValidField('description'))
    a.description = MARKER + ' | table=' + aclName;

  var aclId = a.insert();
  if (!aclId) throw 'Failed to insert field-level ACL for: ' + aclName;
  return aclId;
}

function linkAclToRole(aclSysId, roleSysId) {
  var m = new GlideRecord('sys_security_acl_role');
  m.addQuery('sys_security_acl', aclSysId);
  m.addQuery('sys_user_role', roleSysId);
  m.setLimit(1);
  m.query();
  if (m.next()) return m.getUniqueValue();
  m.initialize();
  m.sys_security_acl = aclSysId;
  m.sys_user_role    = roleSysId;
  var id = m.insert();
  if (!id) throw 'Failed to link ACL to role';
  return id;
}

function processFieldAcls(tables, roleId) {
  for (var i = 0; i < tables.length; i++) {
    var table = tables[i];
    var aclName = table + '.*';
    try {
      // Skip tables that do not exist on this instance
      if (!tableExistsOnInstance(table)) {
        SUMMARY.tablesSkipped.push(aclName + ' (table not found on this instance)');
        continue;
      }

      var existingAclId = ourFieldAclAlreadyExists(table);
      var aclIdToUse = existingAclId;

      if (existingAclId && !FORCE_INSERT) {
        SUMMARY.aclsReused.push(aclName + ' (' + existingAclId + ')');
      } else {
        aclIdToUse = insertFieldAcl(table);
        SUMMARY.aclsCreated.push(aclName + ' (' + aclIdToUse + ')');
      }

      // Ensure the role is linked to this ACL
      linkAclToRole(aclIdToUse, roleId);

    } catch (e) {
      gs.error('Field ACL ' + aclName + ': ' + e);
      SUMMARY.errors.push(aclName + ' — ' + e);
    }
  }
}

// =================================================================================================
// EXECUTE — Run all steps in sequence
// =================================================================================================

try {
  // Step 1: Look up the role (must already exist)
  var roleId = findRoleId(TARGET_ROLE_NAME);
  if (!roleId) {
    throw 'Role "' + TARGET_ROLE_NAME + '" not found. Run the row-level ACL setup script first, ' +
          'or update TARGET_ROLE_NAME to match your existing role.';
  }

  // Step 2: Create/reuse field-level READ ACLs and link them to the role
  processFieldAcls(TABLES, roleId);

} catch (e) {
  gs.error('FATAL: Script aborted — ' + e);
  SUMMARY.errors.push('FATAL: ' + e);
}

// =================================================================================================
// SUMMARY — Print results for review
// =================================================================================================

gs.print('\n--- Field-Level ACL Setup Summary ---');
gs.print('Role:  ' + SUMMARY.role);

if (SUMMARY.aclsCreated.length) {
  gs.print('\nCreated NEW field-level READ ACLs (table.*):\n  - ' + SUMMARY.aclsCreated.join('\n  - '));
}
if (SUMMARY.aclsReused.length) {
  gs.print('\nReused existing ACLs (marker found):\n  - ' + SUMMARY.aclsReused.join('\n  - '));
}
if (SUMMARY.tablesSkipped.length) {
  gs.print('\nSkipped tables:\n  - ' + SUMMARY.tablesSkipped.join('\n  - '));
}

if (SUMMARY.errors.length) {
  gs.warn('\nErrors:\n  - ' + SUMMARY.errors.join('\n  - '));
} else {
  gs.print('\nAll steps completed successfully. No errors.');
}

gs.print('\nAll field-level ACLs are linked to role "' + TARGET_ROLE_NAME + '".');
