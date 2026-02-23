# HelloID-Conn-SA-Full-EntraID-AFAS-Update-UPN-Mail

| :information_source: Information                                                                                                                                                                                                                                                                                                                                                          |
|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| This repository contains the connector and configuration code only. The implementer is responsible for acquiring the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements. |

## Description
_HelloID-Conn-SA-Full-EntraID-AFAS-Update-UPN-Mail_ is a template designed for use with HelloID Service Automation (SA). It can be imported into HelloID and customized according to your requirements. 

By using this delegated form, you can update User Principal Name (UPN), Mail, and Mail Nickname attributes for users in both Microsoft Entra ID and AFAS Profit. The following options are available:
 1. Search and select the user from Entra ID
 2. Enter new values for UPN and/or Mail attributes
 3. Mail Nickname is automatically calculated from the mail address (part before @)
 4. The entered values are validated for uniqueness in Entra ID (checks userPrincipalName, mail, mailNickname, and proxyAddresses)
 5. UPN, Mail, and Mail Nickname attributes are updated in Entra ID
 6. Mail attribute (EmAd) is updated in AFAS Profit (if mail change is requested and employeeID is available)

## Getting started
### Requirements

- **Microsoft Entra ID (Azure AD) App Registration**:<br>
  An app registration must be created in Entra ID with the following permissions:
  - Microsoft Graph API: `User.ReadWrite.All` (Application permission)
  - The app registration must use certificate-based authentication
  
- **SSL Certificate for Entra ID Authentication**:<br>
  A valid SSL certificate must be configured for the app registration. The certificate should be exported as a base64-encoded string with its password. The certificate is used for JWT token generation to authenticate with Microsoft Graph API.

- **AFAS Profit API Access**:<br>
  Access to the AFAS Profit API is required with:
  - A valid AFAS token for authentication
  - Access to the `T4E_HelloID_Users_v2` GET connector: [HelloID-Conn-Prov-Target-AFAS-Profit-Employees](https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-AFAS-Profit-Employees)
  - Access to the `KnEmployee` UPDATE connector for updating employee records

### Connection settings

The following user-defined variables are used by the connector and should be configured in HelloID Service Automation (Automation → Variable library).

#### Entra ID Settings
| Setting                        | Description                                                        | Mandatory |
|--------------------------------|--------------------------------------------------------------------|-----------|
| EntraIdTenantId                | The Tenant ID of your Entra ID environment                         | Yes       |
| EntraIdAppId                   | The Application (Client) ID of the App Registration                | Yes       |
| EntraIdCertificateBase64String | The certificate as a base64-encoded string (including private key) | Yes       |
| EntraIdCertificatePassword     | The password for the certificate                                   | Yes       |

#### AFAS Settings
| Setting     | Description                                                                                          | Mandatory |
|-------------|------------------------------------------------------------------------------------------------------|-----------|
| AFASBaseUrl | The base URL to the AFAS Profit REST API (e.g., `https://12345.rest.afas.online/profitrestservices`) | Yes       |
| AFASToken   | The AFAS token for authentication                                                                    | Yes       |

## Remarks

### Conditional Updates
- **Boolean Controls**: The form includes boolean checkboxes (`blnUPN` and `blnMail`) that allow users to selectively choose which attributes to update. Only the selected attributes will be included in the update request to Entra ID.
- **AFAS Updates**: AFAS employee records are only updated if the mail attribute change is requested (`blnMail` is true) and an `employeeID` is available for the user.

### Uniqueness Validation
- **Comprehensive Validation**: Before updating, the connector validates that the new UPN and mail values are unique in Entra ID. This includes checking:
  - `userPrincipalName` attribute
  - `mail` attribute
  - `mailNickname` attribute (auto-calculated from mail)
  - `proxyAddresses` collection (both SMTP and smtp prefixes)
- **Self-Exclusion**: The validation excludes the current user from the uniqueness check.

### Mail Nickname Auto-Calculation
- **Automatic Calculation**: The Mail Nickname is automatically calculated from the new Mail address by extracting the local part (the part before the @ symbol)
- **User Control**: Users have no direct control over the Mail Nickname value, it is determined automatically by the mail address

### AFAS Employee Correlation
- **Employee ID Matching**: The connector correlates Entra ID users to AFAS employees using the `employeeID` attribute in Entra ID, which should match the `Medewerker` field in AFAS.
- **Skip When Missing**: If no `employeeID` is available for an Entra ID user, the AFAS update will be skipped with an informational message.

## Development resources

### API endpoints

The following endpoints are used by the connector:

#### Microsoft Graph API (Entra ID)
| Endpoint         | Method | Description                                      |
|------------------|--------|--------------------------------------------------|
| /v1.0/users      | GET    | Retrieve all users (used for search/validation)  |
| /v1.0/users/{id} | PATCH  | Update user attributes (UPN, mail, mailNickname) |

#### AFAS Profit REST API
| Endpoint                         | Method | Description                                      |
|----------------------------------|--------|--------------------------------------------------|
| /connectors/T4E_HelloID_Users_v2 | GET    | Retrieve employee information (custom connector) |
| /connectors/KnEmployee           | PUT    | Update employee records (mail attribute)         |

### API documentation

- **Microsoft Graph API**: [https://learn.microsoft.com/en-us/graph/api/overview](https://learn.microsoft.com/en-us/graph/api/overview)
- **Microsoft Graph Users API**: [https://learn.microsoft.com/en-us/graph/api/resources/user](https://learn.microsoft.com/en-us/graph/api/resources/user)
- **AFAS Profit API**: [https://docs.afas.help/profit/](https://docs.afas.help/profit/)

## Getting help
> :bulb: **Tip:**  
> _For more information on Delegated Forms, please refer to our [documentation](https://docs.helloid.com/en/service-automation/delegated-forms.html) pages_.

## HelloID docs
The official HelloID documentation can be found at: https://docs.helloid.com/