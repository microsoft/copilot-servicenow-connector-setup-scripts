// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// =================================================================================================
// ServiceNow Background Script: Create service account and grant row-level read access
// =================================================================================================
//
// PURPOSE
// -------
// This script automates the "Create service account and set up permissions to index items" steps
// documented at:
//   https://learn.microsoft.com/en-us/microsoftsearch/servicenow-knowledge-admin-setup#create-service-account-and-set-up-permissions-to-index-items
//   https://learn.microsoft.com/en-us/microsoftsearch/granting-table-access-servicenow
//
// The ServiceNow Knowledge Microsoft 365 Copilot connector requires a service account with read
// access to specific tables. This script creates that account, assigns the required role, and
// configures row-level READ ACLs for all the tables the connector needs — in a single run.
//
// WHAT THIS SCRIPT DOES (step by step)
// -------------------------------------
// 1. Creates (or reuses) a custom role for the connector service account.
//    - If a role with the configured name already exists, it is reused.
//    - Otherwise a new role is created.
//
// 2. Creates (or reuses) a service account user.
//    - If a user with the configured user_name already exists, it is reused.
//    - Otherwise a new user is created with first_name, last_name, and email.
//
// 3. Maps the custom role to the service account user.
//
// 4. (Optional) Maps additional standard roles to the service account.
//    - By default the list is empty. You can add roles like 'knowledge_admin',
//      'user_criteria_admin', or 'user_admin' if your instance's existing ACL
//      configuration requires them for the connector to function.
//    - See the STANDARD_ROLES_TO_ADD configuration section for details.
//
// 5. Creates record-level READ ACLs for each required table and links them to the custom role.
//    - For each table the script first checks whether the table exists on the instance,
//      and whether an ACL created by a previous run already exists (using a description marker).
//    - If the ACL exists, it is reused. Otherwise a new ACL is created.
//    - The custom role is linked to each ACL via the sys_security_acl_role M2M table.
//
// WHAT THIS SCRIPT DOES NOT DO
// -----------------------------
// - It does NOT create field-level ACLs (table.*). Those are handled by a separate script.
// - It does NOT set up the Scripted REST API. That is handled by a separate script.
// - It does NOT delete or modify any existing ACLs, roles, or users.
// - It does NOT communicate with any service outside your ServiceNow instance.
//
// SAFETY & IDEMPOTENCY
// ---------------------
// - The script is idempotent: running it multiple times produces the same result.
//   Each step checks for existing records before creating new ones.
// - ACLs created by this script are tagged with a description marker so that re-runs
//   can identify and reuse them instead of creating duplicates.
// - All changes are logged in the summary output at the end.
// - If a table does not exist on the instance, it is skipped (not treated as an error).
// - The script uses isValidField() checks to adapt to different ServiceNow versions.
//
// PREREQUISITES
// --------------
// - You must be logged in as an admin (or have the security_admin role elevated).
//
// HOW TO RUN
// -----------
// 1. Navigate to: All > System Definition > Scripts - Background
// 2. Paste this entire script into the editor.
// 3. Click "Run script".
// 4. Review the summary output to confirm all steps completed successfully.
//
// HOW TO VERIFY
// --------------
// After running, verify access:
//   1. Set a password for the service account.
//   2. Use a REST client (e.g., curl or Postman) to query a table as the service account:
//      GET https://<instance>.service-now.com/api/now/table/kb_knowledge?sysparm_limit=1
//   3. If rows are returned but field values are empty, run the separate field-level ACL script.
// =================================================================================================

gs.requireSecurityAdmin();

// =================================================================================================
// CONFIGURATION
// =================================================================================================
// Edit these values to match your deployment. The defaults below align with the Microsoft Learn
// documentation. For most deployments you only need to review the role and user settings.

var ROLE_NAME        = 'copilot_connector';              // Name of the custom role to create.
                                                          // This role will be linked to all ACLs
                                                          // so the service account can read the
                                                          // required tables.

var ROLE_DESC        = 'Read access role for Microsoft 365 Copilot Knowledge connector';

var USER_ID          = 'microsoft.copilot';               // User ID (user_name) for the service account.
                                                          // Must not contain spaces or special characters
                                                          // as it is used in authentication flows.

var USER_FIRST_NAME  = 'Microsoft';                       // First name for the service account.
var USER_LAST_NAME   = 'Copilot';                         // Last name for the service account.
var USER_EMAIL       = '';                                 // Email address (optional).
                                                          // Set this if your organization requires it.

// =================================================================================================
// CONFIGURATION: Optional standard roles
// =================================================================================================
// These standard roles are OPTIONAL. The custom role + per-table ACLs created by this script
// already provide the read access the connector needs for the documented setup.
//
// However, on some instances the out-of-the-box ACL configuration may require the service account
// to hold these standard roles for access to function correctly. They are included here by default
// as a safety net. If you prefer a minimal-permission setup, you can remove any or all of them —
// then verify access by querying a table via REST API as the service account after running the script.
//
// Note that these roles grant broader permissions than just read access:
//   - 'knowledge_admin'       — Full KB administration (create, edit, retire, publish, delete).
//   - 'user_criteria_admin'   — Full user criteria administration.
//   - 'user_admin'            — Full user administration.

var STANDARD_ROLES_TO_ADD = [
  'knowledge_admin',
  'user_criteria_admin',
  'user_admin'
];

// =================================================================================================
// CONFIGURATION: Tables requiring row-level READ access
// =================================================================================================
// These are the tables listed in the Microsoft Learn documentation under
// "Create service account and set up permissions to index items".
// One record-level READ ACL is created per table and linked to the custom role.

// Tables required for BOTH simple and advanced connector flows.
var CORE_TABLES = [
  'kb_knowledge',                  // Crawl knowledge articles
  'kb_knowledge_base',             // Read knowledge base information
  'kb_uc_can_read_mtom',           // Who can read this knowledge base
  'kb_uc_can_contribute_mtom',     // Who can contribute to this knowledge base
  'kb_uc_cannot_read_mtom',        // Who cannot read this knowledge base
  'kb_uc_cannot_contribute_mtom',  // Who cannot contribute to this knowledge base
  'user_criteria',                 // Read user criteria permissions
  'sys_user',                      // Read user table
  'sys_user_group',                // Read user group segments
  'sys_user_role',                 // Read user roles
  'sys_user_grmember',             // Read group membership of users
  'sys_user_has_role',             // Read role information of users
  'sys_attachment',                // Crawl attachments to knowledge articles
  'kb_feedback',                   // Crawl comments on knowledge articles
  'sys_properties',                // Read properties (for hierarchical permission evaluation)
  'sys_db_object',                 // Read extended table details for templates
  'sys_dictionary'                 // Read extended table properties and crawl templates
];

// Tables required ONLY for the "simple" connector flow.
// If you are using the "advanced" flow exclusively, you may remove these.
// Including them when not needed is harmless (extra ACLs do not affect other users).
var SIMPLE_FLOW_TABLES = [
  'cmn_department',                // Read department information
  'cmn_location',                  // Read location information
  'core_company'                   // Read company attributes
];

var TABLES = CORE_TABLES.concat(SIMPLE_FLOW_TABLES);

// =================================================================================================
// CONFIGURATION: ACL settings
// =================================================================================================

var ACL_ORDER    = 50;             // Evaluation order for new ACLs (lower = evaluated earlier).
                                   // The default value of 50 works for most instances.
                                   // Adjust if your instance has custom ordering requirements.

var FORCE_INSERT = false;          // If true, always create a new ACL even when a marker-tagged
                                   // ACL already exists. Not recommended — use only if you need
                                   // to recreate ACLs after a manual deletion of the role link.

// =================================================================================================
// INTERNAL: Derived constants and summary tracker
// =================================================================================================

// Marker written into the ACL description field for idempotency.
// On re-runs the script searches for this marker to identify ACLs it previously created.
var MARKER = 'AUTO-ACL for role=' + ROLE_NAME + ' (KB-connector)';

var SUMMARY = {
  role: '',
  user: '',
  customRoleMapping: '',
  standardRolesMapped: [],
  standardRolesNotFound: [],
  aclsCreated: [],
  aclsReused: [],
  tablesSkipped: [],
  errors: []
};

// =================================================================================================
// UTILITY FUNCTIONS
// =================================================================================================

// Checks whether a table exists on this instance by querying the sys_db_object dictionary.
// Used to skip ACL creation for tables that may not be present on all ServiceNow versions
// (e.g., cmn_department, cmn_location, core_company).
function tableExistsOnInstance(tableName) {
  var gr = new GlideRecord('sys_db_object');
  gr.addQuery('name', tableName);
  gr.setLimit(1);
  gr.query();
  return gr.next();
}

// =================================================================================================
// STEP 1: ROLE — Create or reuse the custom role
// =================================================================================================
// The connector service account needs a role that is linked to the row-level READ ACLs.
// This step creates a dedicated role for that purpose, or reuses it if it already exists.
// The role is created with a descriptive name so it can be easily identified in the UI:
//   User Administration > Roles

function getOrCreateRole(name, desc) {
  var r = new GlideRecord('sys_user_role');
  r.addQuery('name', name);
  r.setLimit(1);
  r.query();
  if (r.next()) {
    SUMMARY.role = 'Role reused: ' + name + ' (' + r.getUniqueValue() + ')';
    return r.getUniqueValue();
  }
  r.initialize();
  r.name = name;
  r.description = desc || name;
  var id = r.insert();
  if (!id) throw 'Failed to create role: ' + name;
  SUMMARY.role = 'Role created: ' + name + ' (' + id + ')';
  return id;
}

// =================================================================================================
// STEP 2: USER — Create or reuse the service account
// =================================================================================================
// Creates a new user record in sys_user with the configured user_name, first_name, last_name,
// and email. This is the account that the Microsoft 365 Copilot connector will authenticate as.
//
// The docs say: "Fill in the user details, such as 'microsoft.copilot' for the User ID
// and 'Microsoft' and 'Copilot' for the First Name and Last Name."
//
// If the user already exists (matched by user_name), it is reused without modification.
// NOTE: password_needs_reset is set to true so the admin can set a password before use.
//
// The 'identity_type' field (introduced in the Zurich release) marks the account as a machine
// identity rather than a human user. This is set via isValidField() so the script remains
// compatible with pre-Zurich instances where the field does not exist.

function getOrCreateUser(userId, firstName, lastName, email) {
  var u = new GlideRecord('sys_user');
  u.addQuery('user_name', userId);
  u.setLimit(1);
  u.query();
  if (u.next()) {
    SUMMARY.user = 'User reused: ' + userId + ' (' + u.getUniqueValue() + ')';
    return u.getUniqueValue();
  }
  u.initialize();
  u.user_name            = userId;
  u.first_name           = firstName || '';
  u.last_name            = lastName || userId;
  u.email                = email || '';
  u.active               = true;
  u.password_needs_reset = true;
  // Mark as machine identity (Zurich+). Skipped silently on older versions.
  if (u.isValidField('identity_type')) u.identity_type = 'machine';
  var id = u.insert();
  if (!id) throw 'Failed to create user: ' + userId;
  SUMMARY.user = 'User created: ' + userId + ' (' + id + ')';
  return id;
}

// =================================================================================================
// STEP 3: MAP ROLE TO USER — Assign the custom role to the service account
// =================================================================================================
// Creates an entry in sys_user_has_role to assign the role to the user.
// Equivalent to adding the role via the "Roles" related list on the user form in the UI.
// If the mapping already exists, it is reused.

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
  if (!id) throw 'Failed to map role to user';
  return id;
}

// =================================================================================================
// STEP 4 (OPTIONAL): MAP STANDARD ROLES — Assign additional OOTB roles if configured
// =================================================================================================
// Iterates over STANDARD_ROLES_TO_ADD and maps each to the service account.
// Each role is looked up by name; if not found on this instance, a warning is logged.
// This step is only executed if STANDARD_ROLES_TO_ADD is non-empty.

function findRoleIdByName(roleName) {
  var r = new GlideRecord('sys_user_role');
  r.addQuery('name', roleName);
  r.setLimit(1);
  r.query();
  return r.next() ? r.getUniqueValue() : null;
}

function mapStandardRoles(userSysId, roleNames) {
  if (!roleNames || roleNames.length === 0) return;
  for (var i = 0; i < roleNames.length; i++) {
    var roleName = roleNames[i];
    var roleId = findRoleIdByName(roleName);
    if (roleId) {
      ensureUserHasRole(userSysId, roleId);
      SUMMARY.standardRolesMapped.push(roleName);
    } else {
      SUMMARY.standardRolesNotFound.push(roleName);
    }
  }
}

// =================================================================================================
// STEP 5: CREATE ROW-LEVEL READ ACLs — Grant the custom role read access to each table
// =================================================================================================
// For each table in the TABLES array, this step:
//   1. Checks if the table exists on this instance (skips if not).
//   2. Checks if an ACL tagged with our marker already exists (reuses if so).
//   3. Creates a new record-level READ ACL if needed.
//   4. Links the custom role to the ACL via sys_security_acl_role.
//
// Each ACL is created with:
//   - Type: record
//   - Operation: read
//   - Name: <table_name>
//   - Active: true
//   - Admin overrides: true
//   - Script: (empty — pure role-based authorization, no script evaluation)
//   - Description: contains the MARKER string for idempotent re-identification

function ourAclAlreadyExists(table) {
  var a = new GlideRecord('sys_security_acl');
  a.addQuery('type', 'record');
  a.addQuery('operation', 'read');
  a.addQuery('name', table);
  a.addQuery('description', 'CONTAINS', MARKER);
  a.setLimit(1);
  a.query();
  return a.next() ? a.getUniqueValue() : null;
}

function insertAcl(table) {
  var a = new GlideRecord('sys_security_acl');
  a.initialize();
  a.type            = 'record';
  a.name            = table;
  a.operation       = 'read';
  a.active          = true;
  a.admin_overrides = true;
  if (a.isValidField('order')) a.order = ACL_ORDER;
  a.script          = '';
  if (a.isValidField('description'))
    a.description = MARKER + ' | table=' + table;

  var aclId = a.insert();
  if (!aclId) throw 'Failed to insert ACL for table: ' + table;
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

function processTableAcls(tables, roleId) {
  for (var i = 0; i < tables.length; i++) {
    var table = tables[i];
    try {
      // Skip tables that do not exist on this instance
      if (!tableExistsOnInstance(table)) {
        SUMMARY.tablesSkipped.push(table + ' (table not found on this instance)');
        continue;
      }

      var existingAclId = ourAclAlreadyExists(table);
      var aclIdToUse = existingAclId;

      if (existingAclId && !FORCE_INSERT) {
        SUMMARY.aclsReused.push(table + ' (' + existingAclId + ')');
      } else {
        aclIdToUse = insertAcl(table);
        SUMMARY.aclsCreated.push(table + ' (' + aclIdToUse + ')');
      }

      // Ensure the custom role is linked to this ACL
      linkAclToRole(aclIdToUse, roleId);

    } catch (e) {
      gs.error('Table ' + table + ': ' + e);
      SUMMARY.errors.push(table + ' — ' + e);
    }
  }
}

// =================================================================================================
// EXECUTE — Run all steps in sequence
// =================================================================================================

try {
  // Step 1: Create or reuse the custom role
  var roleId = getOrCreateRole(ROLE_NAME, ROLE_DESC);

  // Step 2: Create or reuse the service account user
  var userId = getOrCreateUser(USER_ID, USER_FIRST_NAME, USER_LAST_NAME, USER_EMAIL);

  // Step 3: Map the custom role to the user
  ensureUserHasRole(userId, roleId);
  SUMMARY.customRoleMapping = 'User "' + USER_ID + '" mapped to custom role "' + ROLE_NAME + '"';

  // Step 4 (Optional): Map standard roles if configured
  mapStandardRoles(userId, STANDARD_ROLES_TO_ADD);

  // Step 5: Create/reuse row-level READ ACLs and link them to the custom role
  processTableAcls(TABLES, roleId);

} catch (e) {
  gs.error('FATAL: Script aborted — ' + e);
  SUMMARY.errors.push('FATAL: ' + e);
}

// =================================================================================================
// SUMMARY — Print results for review
// =================================================================================================

gs.print('\n--- Row-Level ACL Setup Summary ---');
gs.print('Role:                 ' + SUMMARY.role);
gs.print('User:                 ' + SUMMARY.user);
gs.print('Custom role mapping:  ' + SUMMARY.customRoleMapping);

if (SUMMARY.standardRolesMapped.length) {
  gs.print('Standard roles mapped: ' + SUMMARY.standardRolesMapped.join(', '));
}
if (SUMMARY.standardRolesNotFound.length) {
  gs.warn('Standard roles NOT FOUND (skipped): ' + SUMMARY.standardRolesNotFound.join(', '));
}

if (SUMMARY.aclsCreated.length) {
  gs.print('\nCreated NEW record-level READ ACLs:\n  - ' + SUMMARY.aclsCreated.join('\n  - '));
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

gs.print('\nAll ACLs are linked to custom role "' + ROLE_NAME + '".');
gs.print('Next step: Run the field-level ACL script if field values are not visible when querying tables via REST API.');
