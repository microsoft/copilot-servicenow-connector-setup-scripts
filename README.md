# ServiceNow Knowledge — Microsoft 365 Copilot Connector Setup Scripts

Background scripts that automate the ServiceNow configuration steps required for the [ServiceNow Knowledge Microsoft 365 Copilot connector](https://learn.microsoft.com/en-us/microsoft-365/copilot/connectors/servicenow-knowledge-overview). These scripts perform the same setup you would do manually through the ServiceNow UI, but in a single run.

## Scripts

| Script | Purpose | Documentation Reference |
|--------|---------|------------------------|
| [federated_auth_setup.js](federated_auth_setup.js) | *(Federated Auth deployments only)* Configures OIDC: the provider configuration, the Application Registry entity, the `useraccount` auth scope, and the machine integration user | [Federated Auth (Federated Identity Credentials)](https://learn.microsoft.com/en-us/microsoft-365/copilot/connectors/servicenow-knowledge-deployment#federated-auth-federated-identity-credentials) |
| [row_level_acl_setup.js](row_level_acl_setup.js) | Creates service account, custom role, and row-level READ ACLs for all required tables | [Create service account and set up permissions](https://learn.microsoft.com/en-us/microsoft-365/copilot/connectors/servicenow-knowledge-admin-setup#create-service-account-and-set-up-permissions-to-index-items) / [Grant table access](https://learn.microsoft.com/en-us/microsoft-365/copilot/connectors/granting-table-access-servicenow-knowledge) |
| [field_level_acl_setup.js](field_level_acl_setup.js) | Creates field-level READ ACLs (`table.*`) for tables where field values are restricted | [Grant field-level access](https://learn.microsoft.com/en-us/microsoft-365/copilot/connectors/granting-table-access-servicenow-knowledge#grant-field-level-access) |
| [scripted_rest_api_setup.js](scripted_rest_api_setup.js) | Creates the Scripted REST API endpoint for the Advanced connector flow | [Set up REST API](https://learn.microsoft.com/en-us/microsoft-365/copilot/connectors/servicenow-knowledge-admin-setup#set-up-rest-api) |

## Prerequisites

- ServiceNow admin account with `security_admin` role elevated
- Access to **System Definition > Scripts - Background**

## How to Run

1. **Elevate** your role to `security_admin` in ServiceNow.
2. Navigate to **All > System Definition > Scripts - Background**.
3. Copy a script file and paste it into the script editor.
4. Review the **CONFIGURATION** section at the top of the script. Update values (role name, user ID, etc.) to match your organization's naming conventions if needed.
5. Click **Run script**.
6. Review the output summary to confirm all steps completed successfully.

### Recommended order

> **Using Federated Auth?** If you authenticate the connector with the **Federated Auth (Federated Identity Credentials)** option, run **`federated_auth_setup.js`** first. It creates the machine integration user (keyed by the service principal object ID) that the connector crawls as. Then set that same object ID as `USER_ID` in step 1 so the read role and ACLs are assigned to that integration user. For Basic auth or OAuth 2.0, skip this script and use a service account user ID such as `microsoft.copilot`.

1. **`row_level_acl_setup.js`** — Run first. Creates the service account (or reuses the Federated Auth integration user), role, and row-level ACLs. Set `USER_ID` in the CONFIGURATION section before running — it is required (no default).
2. **Verify** — Set a password for the service account, then use a REST client (e.g., curl or Postman) to query a table as the service account:
   ```
   GET https://<instance>.service-now.com/api/now/table/kb_knowledge?sysparm_limit=1
   ```
   Authenticate with the service account credentials (Basic Auth). If rows are returned with field values populated, skip to step 4. If rows are returned but field values are empty, proceed to step 3.
   > **Note:** On Zurich and later releases, the script marks the service account as a machine identity (`identity_type = machine`), which automatically enables "Web service access only". Machine identity accounts cannot be impersonated through the ServiceNow UI — use the REST API to verify access instead.
3. **`field_level_acl_setup.js`** — Run only if field values are not visible after step 2.
4. **`scripted_rest_api_setup.js`** — If your ServiceNow instance uses advanced scripts in user criteria (rather than simple user/group-based criteria), you should select the **Advanced** flow when configuring the connector in the Microsoft 365 admin center. Run this script to create the Scripted REST API endpoint that the connector calls to resolve user criteria at query time.

## Key Features

- **Idempotent** — Safe to run multiple times. Existing records are reused, not duplicated.
- **Non-destructive** — Scripts do not modify, delete, or overwrite existing records.
- **Self-contained** — No external dependencies or network calls outside your ServiceNow instance.
- **Cross-version compatible** — Uses `isValidField()` checks to adapt to different ServiceNow releases.
- **Transparent** — Every action is logged in the output summary for review.

## Configuration

Each script has a clearly marked **CONFIGURATION** section at the top where you can customize:

- **Role name** — Default: `copilot_connector`
- **Service account user ID** (`USER_ID`) — Required, no default. Use a service account name such as `microsoft.copilot` for Basic auth / OAuth 2.0, or the service principal object ID for Federated Auth.
- **Federated Auth values** (`federated_auth_setup.js`) — Service principal object ID and Microsoft Entra tenant ID (both required to run that script).
- **Table lists** — Add or remove tables based on your instance requirements
- **Optional standard roles** — `knowledge_admin`, `user_criteria_admin`, `user_admin` (included by default in the row-level script as a safety net; can be removed for minimal-permission setups)

## What the Scripts Do NOT Do

- They do **not** set service account passwords — the admin must set the password after running the row-level script.
- They do **not** communicate with any service outside your ServiceNow instance.
- They do **not** install plugins or create application scopes.

## Contributing

This project welcomes contributions and suggestions. Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
