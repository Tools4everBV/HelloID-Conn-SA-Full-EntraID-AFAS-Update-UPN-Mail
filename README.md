# HelloID-Conn-SA-Full-EntraID-AFAS-Update-UPN-Mail

> [!IMPORTANT]
> This repository contains the connector and configuration code only. The implementer is responsible for acquiring the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.

<p align="center">
  <img src="https://github.com/Tools4everBV/HelloID-Conn-SA-Full-EntraID-AFAS-Update-UPN-Mail/blob/main/Logo.png?raw=true">
</p>

## Table of contents

- [HelloID-Conn-SA-Full-EntraID-AFAS-Update-UPN-Mail](#helloid-conn-sa-full-entraid-afas-update-upn-mail)
  - [Table of contents](#table-of-contents)
  - [Requirements](#requirements)
  - [Remarks](#remarks)
  - [Introduction](#introduction)
      - [Description](#description)
      - [Endpoints](#endpoints)
      - [Form Options](#form-options)
      - [Task Actions](#task-actions)
  - [Connector Setup](#connector-setup)
    - [Variable Library - User Defined Variables](#variable-library---user-defined-variables)
  - [Getting help](#getting-help)
  - [HelloID docs](#helloid-docs)

## Requirements
1. **HelloID Environment**:
   - Set up your _HelloID_ environment.
2. **Entra ID**:
   - App registration with `API permissions` of the type `Application`:
      -  `User.ReadWrite.All`
   - The following information for the app registration is needed in HelloID:
      - `Application (client) ID`
      - `Directory (tenant) ID`
      - `Secret Value`
3. **AFAS Profit**:
   - AFAS tenant id
   - AppConnector token
   - Loaded AFAS GetConnector
     - Tools4ever - HelloID - T4E_HelloID_Users_v2.gcn
     - https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-AFAS-Profit-Employees
   - Build-in Profit update connector: KnEmployee

## Remarks
- None at this time.

## Introduction

#### Description
_HelloID-Conn-SA-Full-EntraID-AFAS-Update-UPN-Mail_ is a template designed for use with HelloID Service Automation (SA) Delegated Forms. It can be imported into HelloID and customized according to your requirements. 

By using this delegated form, you can update the UPN and Email in Entra ID and AFAS Profit. The following options are available:
 1. Search and select the Entra ID user
 2. Enter new values for the following Entra ID account attributes: userPrincipalName and mail
 3. The entered userPrincipalName and mail are validated
 4. Entra ID account [userPrincipalName, mail and mailNickname] and AFAS employee [EmAd] attribute are updated with new values
 5. Writing back [EmAd] in AFAS will be skipped if the employee is not found in AFAS

#### Endpoints
Entra Id and AFAS Profit provide a set of REST APIs that allow you to programmatically interact with its data. The API endpoints listed in the table below are used.

| Endpoint                      | Description                        |
| ----------------------------- | ---------------------------------- |
| users                         | The user endpoint of the Graph API |
| profitrestservices/connectors | AFAS endpoint                      |

#### Form Options
The following options are available in the form:

1. **Lookup user**:
   - This Powershell data source runs an Entra ID query to search for matching Entra ID accounts. This data source returns additional attributes that receive the current values for userPrincipalName/mail and also split them into a prefix and a suffix for future uses.
2. **Validate UPN and mail**:
   - This Powershell data source runs an Entra ID query to validate the uniqueness of the new userPrincipalName, mail and mailNickname. The values are also validated in ProxyAddresses. And will return a "Valid" or "Invalid" text. This text is used for validation in the form.

#### Task Actions
The following actions will be performed based on user selections:

1. **Update UPN and mail in Entra ID**:
   - On the Entra ID account the attributes userPrincipalName, mail and mailNickname will be updated.
     - the proxyAddresses is automatically updated by Entra ID by replacing the value in the mail attribute.
2. **Update EmAd in AFAS Profit Employee**:
   - On the AFAS employee the attributes EmAd will be updated.

## Connector Setup
### Variable Library - User Defined Variables
The following user-defined variables are used by the connector. Ensure that you check and set the correct values required to connect to the API.

| Setting          | Description                                                     |
| ---------------- | --------------------------------------------------------------- |
| `EntraTenantId`  | The ID to the Tenant in Microsoft Entra ID                      |
| `EntraAppId`     | The ID to the App Registration in Microsoft Entra ID            |
| `EntraAppSecret` | The Client Secret to the App Registration in Microsoft Entra ID |
| `AFASBaseUrl`    | The URL to the AFAS environment REST service                    |
| `AFASToken`      | The password to the P12 certificate of your service account     |

## Getting help
> [!TIP]
> _For more information on Delegated Forms, please refer to our [documentation](https://docs.helloid.com/en/service-automation/delegated-forms.html) pages_.

> [!TIP]
>  _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_.

## HelloID docs
The official HelloID documentation can be found at: https://docs.helloid.com/
