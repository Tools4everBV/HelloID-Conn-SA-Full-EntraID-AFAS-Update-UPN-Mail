# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#HelloID variables
#Note: when running this script inside HelloID; portalUrl and API credentials are provided automatically (generate and save API credentials first in your admin panel!)
$portalUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("") #Only unique names are supported. Groups must exist!
$delegatedFormCategories = @("Entra ID","User Management") #Only unique names are supported. Categories will be created if not exists
$script:debugLogging = $false #Default value: $false. If $true, the HelloID resource GUIDs will be shown in the logging
$script:duplicateForm = $false #Default value: $false. If $true, the HelloID resource names will be changed to import a duplicate Form
$script:duplicateFormSuffix = "_tmp" #the suffix will be added to all HelloID resource names to generate a duplicate form with different resource names

#The following HelloID Global variables are used by this form. No existing HelloID global variables will be overriden only new ones are created.
#NOTE: You can also update the HelloID Global variable values afterwards in the HelloID Admin Portal: https://<CUSTOMER>.helloid.com/admin/variablelibrary
$globalHelloIDVariables = [System.Collections.Generic.List[object]]@();

#Global variable #1 >> AFASToken
$tmpName = @'
AFASToken
'@ 
$tmpValue = "" 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "True"});

#Global variable #2 >> EntraAppSecret
$tmpName = @'
EntraAppSecret
'@ 
$tmpValue = "" 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "True"});

#Global variable #3 >> EntraTenantId
$tmpName = @'
EntraTenantId
'@ 
$tmpValue = "" 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #4 >> EntraAppId
$tmpName = @'
EntraAppId
'@ 
$tmpValue = "" 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #5 >> AFASBaseUrl
$tmpName = @'
AFASBaseUrl
'@ 
$tmpValue = @'
https://yourtennantid.rest.afas.online/profitrestservices
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});


#make sure write-information logging is visual
$InformationPreference = "continue"

# Check for prefilled API Authorization header
if (-not [string]::IsNullOrEmpty($portalApiBasic)) {
    $script:headers = @{"authorization" = $portalApiBasic}
    Write-Information "Using prefilled API credentials"
} else {
    # Create authorization headers with HelloID API key
    $pair = "$apiKey" + ":" + "$apiSecret"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $key = "Basic $base64"
    $script:headers = @{"authorization" = $Key}
    Write-Information "Using manual API credentials"
}

# Check for prefilled PortalBaseURL
if (-not [string]::IsNullOrEmpty($portalBaseUrl)) {
    $script:PortalBaseUrl = $portalBaseUrl
    Write-Information "Using prefilled PortalURL: $script:PortalBaseUrl"
} else {
    $script:PortalBaseUrl = $portalUrl
    Write-Information "Using manual PortalURL: $script:PortalBaseUrl"
}

# Define specific endpoint URI
$script:PortalBaseUrl = $script:PortalBaseUrl.trim("/") + "/"  

# Make sure to reveive an empty array using PowerShell Core
function ConvertFrom-Json-WithEmptyArray([string]$jsonString) {
    # Running in PowerShell Core?
    if($IsCoreCLR -eq $true){
        $r = [Object[]]($jsonString | ConvertFrom-Json -NoEnumerate)
        return ,$r  # Force return value to be an array using a comma
    } else {
        $r = [Object[]]($jsonString | ConvertFrom-Json)
        return ,$r  # Force return value to be an array using a comma
    }
}

function Invoke-HelloIDGlobalVariable {
    param(
        [parameter(Mandatory)][String]$Name,
        [parameter(Mandatory)][String][AllowEmptyString()]$Value,
        [parameter(Mandatory)][String]$Secret
    )

    $Name = $Name + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        $uri = ($script:PortalBaseUrl + "api/v1/automation/variables/named/$Name")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
    
        if ([string]::IsNullOrEmpty($response.automationVariableGuid)) {
            #Create Variable
            $body = @{
                name     = $Name;
                value    = $Value;
                secret   = $Secret;
                ItemType = 0;
            }    
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl + "api/v1/automation/variable")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $variableGuid = $response.automationVariableGuid

            Write-Information "Variable '$Name' created$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        } else {
            $variableGuid = $response.automationVariableGuid
            Write-Warning "Variable '$Name' already exists$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        }
    } catch {
        Write-Error "Variable '$Name', message: $_"
    }
}

function Invoke-HelloIDAutomationTask {
    param(
        [parameter(Mandatory)][String]$TaskName,
        [parameter(Mandatory)][String]$UseTemplate,
        [parameter(Mandatory)][String]$AutomationContainer,
        [parameter(Mandatory)][String][AllowEmptyString()]$Variables,
        [parameter(Mandatory)][String]$PowershellScript,
        [parameter()][String][AllowEmptyString()]$ObjectGuid,
        [parameter()][String][AllowEmptyString()]$ForceCreateTask,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $TaskName = $TaskName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        $uri = ($script:PortalBaseUrl +"api/v1/automationtasks?search=$TaskName&container=$AutomationContainer")
        $responseRaw = (Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false) 
        $response = $responseRaw | Where-Object -filter {$_.name -eq $TaskName}
    
        if([string]::IsNullOrEmpty($response.automationTaskGuid) -or $ForceCreateTask -eq $true) {
            #Create Task

            $body = @{
                name                = $TaskName;
                useTemplate         = $UseTemplate;
                powerShellScript    = $PowershellScript;
                automationContainer = $AutomationContainer;
                objectGuid          = $ObjectGuid;
                variables           = (ConvertFrom-Json-WithEmptyArray($Variables));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/automationtasks/powershell")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $taskGuid = $response.automationTaskGuid

            Write-Information "Powershell task '$TaskName' created$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        } else {
            #Get TaskGUID
            $taskGuid = $response.automationTaskGuid
            Write-Warning "Powershell task '$TaskName' already exists$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        }
    } catch {
        Write-Error "Powershell task '$TaskName', message: $_"
    }

    $returnObject.Value = $taskGuid
}

function Invoke-HelloIDDatasource {
    param(
        [parameter(Mandatory)][String]$DatasourceName,
        [parameter(Mandatory)][String]$DatasourceType,
        [parameter(Mandatory)][String][AllowEmptyString()]$DatasourceModel,
        [parameter()][String][AllowEmptyString()]$DatasourceStaticValue,
        [parameter()][String][AllowEmptyString()]$DatasourcePsScript,        
        [parameter()][String][AllowEmptyString()]$DatasourceInput,
        [parameter()][String][AllowEmptyString()]$AutomationTaskGuid,
        [parameter(Mandatory)][Ref]$returnObject
    )

    $DatasourceName = $DatasourceName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    $datasourceTypeName = switch($DatasourceType) { 
        "1" { "Native data source"; break} 
        "2" { "Static data source"; break} 
        "3" { "Task data source"; break} 
        "4" { "Powershell data source"; break}
    }
    
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/datasource/named/$DatasourceName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
      
        if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
            #Create DataSource
            $body = @{
                name               = $DatasourceName;
                type               = $DatasourceType;
                model              = (ConvertFrom-Json-WithEmptyArray($DatasourceModel));
                automationTaskGUID = $AutomationTaskGuid;
                value              = (ConvertFrom-Json-WithEmptyArray($DatasourceStaticValue));
                script             = $DatasourcePsScript;
                input              = (ConvertFrom-Json-WithEmptyArray($DatasourceInput));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
      
            $uri = ($script:PortalBaseUrl +"api/v1/datasource")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
              
            $datasourceGuid = $response.dataSourceGUID
            Write-Information "$datasourceTypeName '$DatasourceName' created$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        } else {
            #Get DatasourceGUID
            $datasourceGuid = $response.dataSourceGUID
            Write-Warning "$datasourceTypeName '$DatasourceName' already exists$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        }
    } catch {
      Write-Error "$datasourceTypeName '$DatasourceName', message: $_"
    }

    $returnObject.Value = $datasourceGuid
}

function Invoke-HelloIDDynamicForm {
    param(
        [parameter(Mandatory)][String]$FormName,
        [parameter(Mandatory)][String]$FormSchema,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $FormName = $FormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/forms/$FormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if(([string]::IsNullOrEmpty($response.dynamicFormGUID)) -or ($response.isUpdated -eq $true)) {
            #Create Dynamic form
            $body = @{
                Name       = $FormName;
                FormSchema = (ConvertFrom-Json-WithEmptyArray($FormSchema));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/forms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $formGuid = $response.dynamicFormGUID
            Write-Information "Dynamic form '$formName' created$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        } else {
            $formGuid = $response.dynamicFormGUID
            Write-Warning "Dynamic form '$FormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        }
    } catch {
        Write-Error "Dynamic form '$FormName', message: $_"
    }

    $returnObject.Value = $formGuid
}


function Invoke-HelloIDDelegatedForm {
    param(
        [parameter(Mandatory)][String]$DelegatedFormName,
        [parameter(Mandatory)][String]$DynamicFormGuid,
        [parameter()][Array][AllowEmptyString()]$AccessGroups,
        [parameter()][String][AllowEmptyString()]$Categories,
        [parameter(Mandatory)][String]$UseFaIcon,
        [parameter()][String][AllowEmptyString()]$FaIcon,
        [parameter()][String][AllowEmptyString()]$task,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $delegatedFormCreated = $false
    $DelegatedFormName = $DelegatedFormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$DelegatedFormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if([string]::IsNullOrEmpty($response.delegatedFormGUID)) {
            #Create DelegatedForm
            $body = @{
                name            = $DelegatedFormName;
                dynamicFormGUID = $DynamicFormGuid;
                isEnabled       = "True";
                useFaIcon       = $UseFaIcon;
                faIcon          = $FaIcon;
                task            = ConvertFrom-Json -inputObject $task;
            }
            if(-not[String]::IsNullOrEmpty($AccessGroups)) { 
                $body += @{
                    accessGroups    = (ConvertFrom-Json-WithEmptyArray($AccessGroups));
                }
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Information "Delegated form '$DelegatedFormName' created$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
            $delegatedFormCreated = $true

            $bodyCategories = $Categories
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$delegatedFormGuid/categories")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $bodyCategories
            Write-Information "Delegated form '$DelegatedFormName' updated with categories"
        } else {
            #Get delegatedFormGUID
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Warning "Delegated form '$DelegatedFormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
        }
    } catch {
        Write-Error "Delegated form '$DelegatedFormName', message: $_"
    }

    $returnObject.value.guid = $delegatedFormGuid
    $returnObject.value.created = $delegatedFormCreated
}


<# Begin: HelloID Global Variables #>
foreach ($item in $globalHelloIDVariables) {
	Invoke-HelloIDGlobalVariable -Name $item.name -Value $item.value -Secret $item.secret 
}
<# End: HelloID Global Variables #>


<# Begin: HelloID Data sources #>
<# Begin: DataSource "EntraID-AFAS-account-update-upn-mail-lookup-user-generate-table" #>
$tmpPsScript = @'
#######################################################################
# Template: HelloID SA Powershell data source
# Name:     EntraID-AFAS-account-update-upn-mail-lookup-user-generate-table
# Date:     12-09-2024
#######################################################################

# For basic information about powershell data sources see:
# https://docs.helloid.com/en/service-automation/dynamic-forms/data-sources/powershell-data-sources/add,-edit,-or-remove-a-powershell-data-source.html#add-a-powershell-data-source

# Service automation variables:
# https://docs.helloid.com/en/service-automation/service-automation-variables/service-automation-variable-reference.html

#region init

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# global variables (Automation --> Variable libary):

# variables configured in form:
$searchValue = $dataSource.searchUser
$searchQuery = "*$searchValue*"

#endregion init

#region functions
function Get-ErrorMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber    = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line                = $ErrorObject.InvocationInfo.Line
            VerboseErrorMessage = $ErrorObject.Exception.Message
            AuditErrorMessage   = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.VerboseErrorMessage = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.VerboseErrorMessage = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.VerboseErrorMessage | ConvertFrom-Json)
            # Make sure to inspect the error result object and add only the error message as a FriendlyMessage.
            $httpErrorObj.VerboseErrorMessage = $errorDetailsObject.error
            $httpErrorObj.AuditErrorMessage = $errorDetailsObject.error.message
            if ($null -eq $httpErrorObj.AuditErrorMessage) {
                $httpErrorObj.AuditErrorMessage = $errorDetailsObject.error
            }
        }
        catch {
            $httpErrorObj.AuditErrorMessage = $httpErrorObj.VerboseErrorMessage
        }
        Write-Output $httpErrorObj
    }
}
#endregion functions

#region lookup
try {          
    Write-Verbose "Generating Microsoft Graph API Access Token.."
    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$EntraTenantId/oauth2/token"
    $body = @{
        grant_type    = "client_credentials"
        client_id     = "$EntraAppId"
        client_secret = "$EntraAppSecret"
        resource      = "https://graph.microsoft.com"
    }

    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;
    Write-Information "Searching for: $searchQuery"
    
    #Add the authorization header to the request
    $authorization = @{
        Authorization  = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept         = "application/json";
    }

    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/users" + '?$select=Id,userPrincipalName,displayName,EmployeeID,proxyAddresses,mail,mailNickname' + '&$top=999'

    $entraIDUsersResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
    $entraIDUsers = $entraIDUsersResponse.value
    while (![string]::IsNullOrEmpty($entraIDUsersResponse.'@odata.nextLink')) {
        $entraIDUsersResponse = Invoke-RestMethod -Uri $entraIDUsersResponse.'@odata.nextLink' -Method Get -Headers $authorization -Verbose:$false
        $entraIDUsers += $entraIDUsersResponse.value
    }  

    $users = foreach ($entraIDUser in $entraIDUsers) {
        if ($entraIDUser.displayName -like $searchQuery -or $entraIDUser.userPrincipalName -like $searchQuery) {
            $entraIDUser
        }
    }
    $users = $users | Sort-Object -Property DisplayName
    $resultCount = @($users).Count
    Write-Information "Result count: $resultCount"

    if (($users | Measure-Object).Count -gt 0) {
        foreach ($user in $users) {
            # Split userPrincipalName and EmailAddress for semperate editing
            if (-not([string]::IsNullOrEmpty($user.userPrincipalName))) {
                $userPrincipalNameSplit = $($user.userPrincipalName).Split("@")
                $userPrincipalNamePrefix = $userPrincipalNameSplit[0]
                $userPrincipalNameSuffix = "@" + $userPrincipalNameSplit[1]
            }
            if (-not([string]::IsNullOrEmpty($user.mail))) {
                $emailAddressSplit = $($user.mail).Split("@")
                $mailPrefix = $emailAddressSplit[0]
                $mailSuffix = "@" + $emailAddressSplit[1]
            }
            $returnObject = @{
                Id                      = $user.Id
                DisplayName             = $user.DisplayName
                EmployeeID              = $user.EmployeeID
                Mail                    = $user.mail
                MailPrefix              = $mailPrefix
                MailSuffix              = $mailSuffix
                MailNickname            = $user.mailNickname
                UserPrincipalName       = $user.UserPrincipalName
                UserPrincipalNamePrefix = $userPrincipalNamePrefix
                UserPrincipalNameSuffix = $userPrincipalNameSuffix
                ProxyAddresses          = $user.proxyAddresses
            }    
            Write-Output $returnObject      
        }
    }
}
catch {
    $ex = $PSItem

    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line [$($errorMessage.InvocationInfo.ScriptLineNumber)]: $($errorMessage.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))" 
    Write-Error "Error searching for Entra ID users. Error: $($errorMessage.AuditErrorMessage)"
}
#endregion lookup
'@ 
$tmpModel = @'
[{"key":"MailSuffix","type":0},{"key":"Mail","type":0},{"key":"MailNickname","type":0},{"key":"MailPrefix","type":0},{"key":"DisplayName","type":0},{"key":"Id","type":0},{"key":"ProxyAddresses","type":0},{"key":"UserPrincipalNamePrefix","type":0},{"key":"UserPrincipalName","type":0},{"key":"EmployeeID","type":0},{"key":"UserPrincipalNameSuffix","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"searchUser","type":0,"options":1}]
'@ 
$dataSourceGuid_0 = [PSCustomObject]@{} 
$dataSourceGuid_0_Name = @'
EntraID-AFAS-account-update-upn-mail-lookup-user-generate-table
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_0_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_0) 
<# End: DataSource "EntraID-AFAS-account-update-upn-mail-lookup-user-generate-table" #>

<# Begin: DataSource "EntraID-AFAS-account-update-upn-mail-validation" #>
$tmpPsScript = @'
#######################################################################
# Template: HelloID SA Powershell data source
# Name:     EntraID-AFAS-account-update-upn-mail-validation
# Date:     12-09-2024
#######################################################################

# For basic information about powershell data sources see:
# https://docs.helloid.com/en/service-automation/dynamic-forms/data-sources/powershell-data-sources/add,-edit,-or-remove-a-powershell-data-source.html#add-a-powershell-data-source

# Service automation variables:
# https://docs.helloid.com/en/service-automation/service-automation-variables/service-automation-variable-reference.html

#region init

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

$outputText = [System.Collections.Generic.List[PSCustomObject]]::new()


# global variables (Automation --> Variable libary):
# $globalVar = $globalVarName

# variables configured in form:
$upnmailEqual = $datasource.upnmailEqual
$userId = $dataSource.selectedUser.Id

$upnCurrent = $dataSource.selectedUser.UserPrincipalName
$upnPrefixNew = $datasource.upnPrefix
$upnSuffixCurrent = $datasource.upnSuffixCurrent
$upnSuffixNew = $datasource.upnSuffixNew
if ([string]::IsNullOrEmpty($upnSuffixNew)) {
    $upnNew = $upnPrefixNew + $upnSuffixCurrent
}
else {
    $upnNew = $upnPrefixNew + $upnSuffixNew
}

if ($upnmailEqual -eq "True") {
    $mailOrUpnNew = $upnNew
    $upnSplit = $($upnNew).Split("@")
    $mailNickNameNew = $upnSplit[0]
}
else {
    $mailNickNameCurrent = $dataSource.selectedUser.MailNickName
    $mailNickNameNew = $datasource.mailNickName
    $mailPrefixNew = $datasource.mailPrefix
    $mailCurrent = $dataSource.selectedUser.Mail
    $mailPrefixNew = $datasource.mailPrefix
    $mailSuffixCurrent = $datasource.mailSuffixCurrent
    $mailSuffixNew = $datasource.mailSuffixNew
    if ([string]::IsNullOrEmpty($mailSuffixNew)) {
        $mailOrUpnNew = $mailPrefixNew + $mailSuffixCurrent
    }
    else {
        $mailOrUpnNew = $mailPrefixNew + $mailSuffixNew
    }
    
}
#endregion init

#region functions
function Get-ErrorMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber    = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line                = $ErrorObject.InvocationInfo.Line
            VerboseErrorMessage = $ErrorObject.Exception.Message
            AuditErrorMessage   = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.VerboseErrorMessage = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.VerboseErrorMessage = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.VerboseErrorMessage | ConvertFrom-Json)
            # Make sure to inspect the error result object and add only the error message as a FriendlyMessage.
            $httpErrorObj.VerboseErrorMessage = $errorDetailsObject.error
            $httpErrorObj.AuditErrorMessage = $errorDetailsObject.error.message
            if ($null -eq $httpErrorObj.AuditErrorMessage) {
                $httpErrorObj.AuditErrorMessage = $errorDetailsObject.error
            }
        }
        catch {
            $httpErrorObj.AuditErrorMessage = $httpErrorObj.VerboseErrorMessage
        }
        Write-Output $httpErrorObj
    }
}
#endregion functions

#region lookup
try {
    if ($upnCurrent -eq $upnNew) {
        $outputText.Add([PSCustomObject]@{
                Message  = "UPN [$upnCurrent] not changed"
                IsError  = $true
                Property = "UPN"
            })
    }

    if (($mailCurrent -eq $mailOrUpnNew)) {
        $outputText.Add([PSCustomObject]@{
                Message  = "mail [$mailCurrent] not changed"
                IsError  = $true
                Property = "mail"
            })
    }

    if (($mailNickNameCurrent -eq $mailNickNameNew)) {
        $outputText.Add([PSCustomObject]@{
                Message  = "mail nickname [$mailNickNameCurrent] not changed"
                IsError  = $true
                Property = "mailNickName"
            })
    }
    
    if (-not($outputText.isError -contains - $true)) {
        write-information "no errors, checking Entra ID for uniqueness"
        
        Write-Verbose "Generating Microsoft Graph API Access Token.."
        $baseUri = "https://login.microsoftonline.com/"
        $authUri = $baseUri + "$EntraTenantId/oauth2/token"
        $body = @{
            grant_type    = "client_credentials"
            client_id     = "$EntraAppId"
            client_secret = "$EntraAppSecret"
            resource      = "https://graph.microsoft.com"
        }
    
        $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
        $accessToken = $Response.access_token;
        
        #Add the authorization header to the request
        $authorization = @{
            Authorization  = "Bearer $accesstoken";
            'Content-Type' = "application/json";
            Accept         = "application/json";
        }

        $graphApiUrl = "https://graph.microsoft.com/v1.0/users"
        $select = '&$select=id,displayName,userPrincipalName,mail,mailNickName,proxyAddresses' + '&$top=999'
        $searchUri = $graphApiUrl + '?$filter' + "=userPrincipalName eq '$upnNew' or mail eq '$mailOrUpnNew' or mailNickname eq '$mailNickNameNew' or proxyAddresses/any(p:p eq '$upnNew') or proxyAddresses/any(p:p eq '$mailOrUpnNew')" + $select

        $entraIDUserParams = @{
            Uri     = $searchUri
            Method  = 'Get'
            Headers = $authorization
            Verbose = $false
        }

        $entraIDUsersResponse = Invoke-RestMethod @entraIDUserParams

        $entraIDUsers = $entraIDUsersResponse.value
        while (![string]::IsNullOrEmpty($entraIDUsersResponse.'@odata.nextLink')) {
            $entraIDUsersResponse = Invoke-RestMethod -Uri $entraIDUsersResponse.'@odata.nextLink' -Method Get -Headers $authorization -Verbose:$false
            $entraIDUsers += $entraIDUsersResponse.value
        }  

        
        write-warning "user: [$($entraIDUsers | ConvertTo-Json)]"

        # Filter out the user that will be updated
        $filteredEntraIDUsers = $entraIDUsers | Where-Object { $_.id -ne $userId }

        write-warning "filteredUsers: [$($filteredEntraIDUsers | ConvertTo-Json)]"

        foreach ($record in $filteredEntraIDUsers) {
            if ($record.userPrincipalName -eq $upnNew) {
                $outputText.Add([PSCustomObject]@{
                        Message  = "UPN [$upnNew] not unique, found on [$($record.displayName)]"
                        IsError  = $true
                        Property = "UPN"
                    })
            }
            if ($record.mailNickName -eq $mailNickNameNew) {
                $outputText.Add([PSCustomObject]@{
                        Message  = "mailNickName [$mailNickNameNew] not unique, found on [$($record.displayName)]"
                        IsError  = $true
                        Property = "mailNickName"
                    })
            }
            if ($record.mail -eq $mailOrUpnNew) {
                $outputText.Add([PSCustomObject]@{
                        Message  = "mail [$mailOrUpnNew] not unique, found on [$($record.displayName)]"
                        IsError  = $true
                        Property = "mail"
                    })
            }
            elseif (($record.proxyAddresses -eq "SMTP:$mailOrUpnNew") -or ($record.proxyAddresses -eq "smtp:$mailOrUpnNew")) {
                $outputText.Add([PSCustomObject]@{
                        Message  = "ProxyAddress [$mailOrUpnNew] not unique, found on [$($record.displayName)]"
                        IsError  = $true
                        Property = "proxyAddresses"
                    })
            }
            elseif (($record.proxyAddresses -eq "SMTP:$upnNew") -or ($record.proxyAddresses -eq "smtp:$upnNew") -and ($upnNew -ne $mailOrUpnNew)) {
                $outputText.Add([PSCustomObject]@{
                        Message  = "ProxyAddress [$upnNew] not unique, found on [$($record.displayName)]"
                        IsError  = $true
                        Property = "proxyAddresses"
                    })
            }
            
        }
    }

    if ($outputText.isError -contains - $true) {
        $outputMessage = "Invalid"
    }
    else {
        $outputMessage = "Valid"
        $outputText.Add([PSCustomObject]@{
                Message  = "UPN [$upnNew] unique"
                IsError  = $false
                Property = "UPN"
            })
        $outputText.Add([PSCustomObject]@{
                Message  = "mail [$mailOrUpnNew] unique"
                IsError  = $false
                Property = "mail"
            })
        $outputText.Add([PSCustomObject]@{
                Message  = "mailNickName [$mailNickNameNew] unique"
                IsError  = $false
                Property = "mail"
            })
    }

    foreach ($text in $outputText) {
        $outputMessage += " | " + $($text.Message)
    }

    $returnObject = @{
        text              = $outputMessage
        userPrincipalName = $upnNew
        mail              = $mailOrUpnNew
        mailNickName      = $mailNickNameNew
    }

    Write-Output $returnObject      
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line [$($errorMessage.InvocationInfo.ScriptLineNumber)]: $($errorMessage.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))" 
    Write-Error "Error querying data Entra ID user [$userId]. Error: $($errorMessage.AuditErrorMessage)"
}    
#endregion lookup
'@ 
$tmpModel = @'
[{"key":"text","type":0},{"key":"userPrincipalName","type":0},{"key":"mailNickName","type":0},{"key":"mail","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"mailPrefix","type":0,"options":0},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"mailSuffixCurrent","type":0,"options":0},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"mailSuffixNew","type":0,"options":0},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"selectedUser","type":0,"options":0},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"upnPrefix","type":0,"options":0},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"upnSuffixCurrent","type":0,"options":0},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"upnSuffixNew","type":0,"options":0},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"upnMailEqual","type":0,"options":0},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"mailNickName","type":0,"options":0}]
'@ 
$dataSourceGuid_1 = [PSCustomObject]@{} 
$dataSourceGuid_1_Name = @'
EntraID-AFAS-account-update-upn-mail-validation
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_1_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_1) 
<# End: DataSource "EntraID-AFAS-account-update-upn-mail-validation" #>
<# End: HelloID Data sources #>

<# Begin: Dynamic Form "Entra ID AFAS Account - Update UPN - Mail" #>
$tmpSchema = @"
[{"label":"Select user account","fields":[{"key":"searchfield","templateOptions":{"label":"Search","placeholder":"Username or Email"},"type":"input","summaryVisibility":"Hide element","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"gridUsers","templateOptions":{"label":"Select user account","required":true,"grid":{"columns":[{"headerName":"Employee ID","field":"EmployeeID"},{"headerName":"Display Name","field":"DisplayName"},{"headerName":"User Principal Name","field":"UserPrincipalName"},{"headerName":"Mail","field":"Mail"},{"headerName":"Mail Nickname","field":"MailNickname"}],"height":300,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[{"propertyName":"searchUser","otherFieldValue":{"otherFieldKey":"searchfield"}}]}},"useFilter":false,"allowCsvDownload":true},"type":"grid","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":true}]},{"label":"Details","fields":[{"key":"formRowUPN","templateOptions":{},"fieldGroup":[{"key":"upnPrefix","templateOptions":{"label":"Current user principal name prefix","useDependOn":true,"dependOn":"gridUsers","dependOnProperty":"UserPrincipalNamePrefix","pattern":"^[a-zA-Z0-9_%+-]+(\\.[a-zA-Z0-9_%+-]+)*","required":true},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"upnSuffixCurrent","templateOptions":{"label":"Current user principal name suffix","useDependOn":true,"dependOn":"gridUsers","dependOnProperty":"UserPrincipalNameSuffix","readonly":true},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"upnSuffixNew","templateOptions":{"label":"New user principal name suffix","required":false,"useObjects":false,"useDataSource":false,"useFilter":false,"options":["@Option1.com","@Option2.com","@Option3.com"]},"type":"dropdown","summaryVisibility":"Show","textOrLabel":"text","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false}],"type":"formrow","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"upnMailEqual","templateOptions":{"label":"User principal name, mail and mail nickname have the same value","useSwitch":true,"checkboxLabel":""},"type":"boolean","defaultValue":true,"summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"formRowMail","templateOptions":{},"fieldGroup":[{"key":"mailPrefix","templateOptions":{"label":"Current mail prefix","useDependOn":true,"dependOn":"gridUsers","dependOnProperty":"MailPrefix","readonly":false,"pattern":"^[a-zA-Z0-9_%+-]+(\\.[a-zA-Z0-9_%+-]+)*"},"validation":{"messages":{"pattern":""}},"hideExpression":"model[\"upnMailEqual\"]","type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"mailSuffixCurrent","templateOptions":{"label":"Current mail suffix","useDependOn":true,"dependOn":"gridUsers","dependOnProperty":"MailSuffix","readonly":true},"validation":{"messages":{"pattern":""}},"hideExpression":"model[\"upnMailEqual\"]","type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"mailSuffixNew","templateOptions":{"label":"New mail suffix","required":false,"useObjects":false,"useDataSource":false,"useFilter":false,"options":["@Option1.com","@Option2.com","@Option3.com"]},"hideExpression":"model[\"upnMailEqual\"]","type":"dropdown","summaryVisibility":"Show","textOrLabel":"text","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false}],"type":"formrow","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"mailNickName","templateOptions":{"label":"Current mail nickname","useDependOn":true,"dependOn":"gridUsers","dependOnProperty":"MailNickname"},"hideExpression":"model[\"upnMailEqual\"]","type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"validate","templateOptions":{"label":"Validation","readonly":true,"required":true,"pattern":"^Valid.*","useDataSource":true,"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_1","input":{"propertyInputs":[{"propertyName":"mailPrefix","otherFieldValue":{"otherFieldKey":"mailPrefix"}},{"propertyName":"mailSuffixCurrent","otherFieldValue":{"otherFieldKey":"mailSuffixCurrent"}},{"propertyName":"mailSuffixNew","otherFieldValue":{"otherFieldKey":"mailSuffixNew"}},{"propertyName":"selectedUser","otherFieldValue":{"otherFieldKey":"gridUsers"}},{"propertyName":"upnPrefix","otherFieldValue":{"otherFieldKey":"upnPrefix"}},{"propertyName":"upnSuffixCurrent","otherFieldValue":{"otherFieldKey":"upnSuffixCurrent"}},{"propertyName":"upnSuffixNew","otherFieldValue":{"otherFieldKey":"upnSuffixNew"}},{"propertyName":"upnMailEqual","otherFieldValue":{"otherFieldKey":"upnMailEqual"}},{"propertyName":"mailNickName","otherFieldValue":{"otherFieldKey":"mailNickName"}}]}},"displayField":"text","minLength":1},"validation":{"messages":{"pattern":"No valid value"}},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false}]}]
"@ 

$dynamicFormGuid = [PSCustomObject]@{} 
$dynamicFormName = @'
Entra ID AFAS Account - Update UPN - Mail
'@ 
Invoke-HelloIDDynamicForm -FormName $dynamicFormName -FormSchema $tmpSchema  -returnObject ([Ref]$dynamicFormGuid) 
<# END: Dynamic Form #>

<# Begin: Delegated Form Access Groups and Categories #>
$delegatedFormAccessGroupGuids = @()
if(-not[String]::IsNullOrEmpty($delegatedFormAccessGroupNames)){
    foreach($group in $delegatedFormAccessGroupNames) {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/groups/$group")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
            $delegatedFormAccessGroupGuid = $response.groupGuid
            $delegatedFormAccessGroupGuids += $delegatedFormAccessGroupGuid
            
            Write-Information "HelloID (access)group '$group' successfully found$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormAccessGroupGuid })"
        } catch {
            Write-Error "HelloID (access)group '$group', message: $_"
        }
    }
    if($null -ne $delegatedFormAccessGroupGuids){
        $delegatedFormAccessGroupGuids = ($delegatedFormAccessGroupGuids | Select-Object -Unique | ConvertTo-Json -Depth 100 -Compress)
    }
}

$delegatedFormCategoryGuids = @()
foreach($category in $delegatedFormCategories) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories/$category")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $response = $response | Where-Object {$_.name.en -eq $category}
        
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        
        Write-Information "HelloID Delegated Form category '$category' successfully found$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    } catch {
        Write-Warning "HelloID Delegated Form category '$category' not found"
        $body = @{
            name = @{"en" = $category};
        }
        $body = ConvertTo-Json -InputObject $body -Depth 100

        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid

        Write-Information "HelloID Delegated Form category '$category' successfully created$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    }
}
$delegatedFormCategoryGuids = (ConvertTo-Json -InputObject $delegatedFormCategoryGuids -Depth 100 -Compress)
<# End: Delegated Form Access Groups and Categories #>

<# Begin: Delegated Form #>
$delegatedFormRef = [PSCustomObject]@{guid = $null; created = $null} 
$delegatedFormName = @'
Entra ID AFAS Account - Update UPN - Mail
'@
$tmpTask = @'
{"name":"Entra ID AFAS Account - Update UPN - Mail","script":"#######################################################################\r\n# Template: HelloID SA Delegated form task\r\n# Name:     EntraID-account-update-upn-mail\r\n# Date:     12-09-2024\r\n#######################################################################\r\n\r\n# For basic information about delegated form tasks see:\r\n# https://docs.helloid.com/en/service-automation/delegated-forms/delegated-form-powershell-scripts/add-a-powershell-script-to-a-delegated-form.html\r\n\r\n# Service automation variables:\r\n# https://docs.helloid.com/en/service-automation/service-automation-variables/service-automation-variable-reference.html\r\n\r\n#region init\r\n# Set TLS to accept TLS, TLS 1.1 and TLS 1.2\r\n[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12\r\n\r\n$VerbosePreference = \"SilentlyContinue\"\r\n$InformationPreference = \"Continue\"\r\n$WarningPreference = \"Continue\"\r\n\r\n# global variables (Automation --> Variable libary):\r\n# $globalVar = $globalVarName\r\n\r\n# variables configured in form:\r\n$entraidGUID = $form.gridUsers.Id\r\n$displayname = $form.gridUsers.DisplayName\r\n$employeeID = $form.gridUsers.employeeID\r\n\r\n\r\n$currentUPN = $form.gridUsers.UserPrincipalName\r\n$upnPrefixNew = $form.upnPrefix\r\n$upnSuffixCurrent = $form.upnSuffixCurrent\r\n$upnSuffixNew = $form.upnSuffixNew\r\n\r\n$currentMail = $form.gridUsers.Mail\r\n$mailPrefixNew = $form.mailPrefix\r\n$mailSuffixCurrent = $form.mailSuffixCurrent\r\n$mailSuffixNew = $form.mailSuffixNew\r\n\r\n$currentMailNickName = $form.gridUsers.MailNickname\r\n$newMailNickName = $form.mailNickName\r\n\r\n$upnMailEqual = $form.upnMailEqual\r\n#endregion init\r\n\r\n#region global\r\n\r\nif ([string]::IsNullOrEmpty($upnSuffixNew)) {\r\n    $newUPN = $upnPrefixNew + $upnSuffixCurrent\r\n}\r\nelse {\r\n    $newUPN = $upnPrefixNew + $upnSuffixNew\r\n}\r\n\r\nif ($upnMailEqual -eq \"True\") {\r\n    $newMail = $newUPN\r\n    $newUPNNameSplit = $($newUPN).Split(\"@\")\r\n    $newMailNickName = $newUPNNameSplit[0]\r\n}\r\nelse {\r\n    if ([string]::IsNullOrEmpty($mailSuffixNew)) {\r\n        $newMail = $mailPrefixNew + $mailSuffixCurrent\r\n    }\r\n    else {\r\n        $newMail = $mailPrefixNew + $mailSuffixNew\r\n    }\r\n}\r\n#endregion global\r\n\r\n#region Entra ID functions\r\nfunction Get-ErrorMessage {\r\n    [CmdletBinding()]\r\n    param (\r\n        [Parameter(Mandatory)]\r\n        [object]\r\n        $ErrorObject\r\n    )\r\n    process {\r\n        $httpErrorObj = [PSCustomObject]@{\r\n            ScriptLineNumber    = $ErrorObject.InvocationInfo.ScriptLineNumber\r\n            Line                = $ErrorObject.InvocationInfo.Line\r\n            VerboseErrorMessage = $ErrorObject.Exception.Message\r\n            AuditErrorMessage   = $ErrorObject.Exception.Message\r\n        }\r\n        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {\r\n            $httpErrorObj.VerboseErrorMessage = $ErrorObject.ErrorDetails.Message\r\n        }\r\n        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {\r\n            if ($null -ne $ErrorObject.Exception.Response) {\r\n                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()\r\n                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {\r\n                    $httpErrorObj.VerboseErrorMessage = $streamReaderResponse\r\n                }\r\n            }\r\n        }\r\n        try {\r\n            $errorDetailsObject = ($httpErrorObj.VerboseErrorMessage | ConvertFrom-Json)\r\n            # Make sure to inspect the error result object and add only the error message as a FriendlyMessage.\r\n            $httpErrorObj.VerboseErrorMessage = $errorDetailsObject.error\r\n            $httpErrorObj.AuditErrorMessage = $errorDetailsObject.error.message\r\n            if ($null -eq $httpErrorObj.AuditErrorMessage) {\r\n                $httpErrorObj.AuditErrorMessage = $errorDetailsObject.error\r\n            }\r\n        }\r\n        catch {\r\n            $httpErrorObj.AuditErrorMessage = $httpErrorObj.VerboseErrorMessage\r\n        }\r\n        Write-Output $httpErrorObj\r\n    }\r\n}\r\n#endregion Entra ID functions\r\n\r\n#region EntraID\r\ntry {\r\n    $account = [PSCustomObject]@{   \r\n        userPrincipalName = $newUPN\r\n        mail              = $newMail\r\n        mailNickname      = $newMailNickName \r\n    }\r\n\r\n    $baseUri = \"https://login.microsoftonline.com/\"\r\n    $authUri = $baseUri + \"$EntraTenantId/oauth2/token\"\r\n\r\n    $body = @{\r\n        grant_type    = \"client_credentials\"\r\n        client_id     = \"$EntraAppId\"\r\n        client_secret = \"$EntraAppSecret\"\r\n        resource      = \"https://graph.microsoft.com\"\r\n    }\r\n \r\n    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'\r\n    $accessToken = $Response.access_token;\r\n \r\n    #Add the authorization header to the request\r\n    $authorization = @{\r\n        Authorization  = \"Bearer $accesstoken\";\r\n        'Content-Type' = \"application/json\";\r\n        Accept         = \"application/json\";\r\n    }\r\n \r\n    $baseUpdateUri = \"https://graph.microsoft.com/\"\r\n    $updateUri = $baseUpdateUri + \"v1.0/users/$($entraidGUID)\"\r\n    $body = $account | ConvertTo-Json -Depth 10\r\n\r\n    $response = Invoke-RestMethod -Uri $updateUri -Method PATCH -Headers $authorization -Body $body -Verbose:$false\r\n        \r\n    Write-Information \"Finished updating Entra ID user [$displayname] attributes [userPrincipalName] from [$currentUPN] to [$newUPN], [mail] from [$currentMail] to [$newMail] and [mailNickname] from [$currentMailNickName] to [$newMailNickName]\"\r\n    $Log = @{\r\n        Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n        System            = \"Entra ID\" # optional (free format text) \r\n        Message           = \"Successfully updated Entra ID user [$displayname] attributes [userPrincipalName] from [$currentUPN] to [$newUPN], [mail] from [$currentMail] to [$newMail] and [mailNickname] from [$currentMailNickName] to [$newMailNickName]\"\r\n        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n        TargetDisplayName = $displayname # optional (free format text) \r\n        TargetIdentifier  = $([string]$entraidGUID) # optional (free format text) \r\n    }\r\n    #send result back  \r\n    Write-Information -Tags \"Audit\" -MessageData $log    \r\n}\r\ncatch {\r\n    $ex = $PSItem\r\n    $errorMessage = Get-ErrorMessage -ErrorObject $ex\r\n\r\n    Write-Verbose \"Error at Line [$($errorMessage.InvocationInfo.ScriptLineNumber)]: $($errorMessage.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))\" \r\n    Write-Error \"Failed to update Entra ID user [$displayname] attributes [userPrincipalName] from [$currentUPN] to [$newUPN], [mail] from [$currentMail] to [$newMail] and [mailNickname] from [$currentMailNickName] to [$newMailNickName]. Error: $($errorMessage.AuditErrorMessage)\"\r\n    $Log = @{\r\n        Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n        System            = \"Entra ID\" # optional (free format text) \r\n        Message           = \"Failed to update Entra ID user [$displayname] attributes [userPrincipalName] from [$currentUPN] to [$newUPN], [mail] from [$currentMail] to [$newMail] and [mailNickname] from [$currentMailNickName] to [$newMailNickName]\"\r\n        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n        TargetDisplayName = $displayname # optional (free format text) \r\n        TargetIdentifier  = $([string]$entraidGUID) # optional (free format text) \r\n    }\r\n    #send result back  \r\n    Write-Information -Tags \"Audit\" -MessageData $log      \r\n}\r\n#endregion EntraID\r\n\r\n#region AFAS\r\nfunction Resolve-HTTPError {\r\n    [CmdletBinding()]\r\n    param (\r\n        [Parameter(Mandatory,\r\n            ValueFromPipeline\r\n        )]\r\n        [object]$ErrorObject\r\n    )\r\n    process {\r\n        $httpErrorObj = [PSCustomObject]@{\r\n            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId\r\n            MyCommand             = $ErrorObject.InvocationInfo.MyCommand\r\n            RequestUri            = $ErrorObject.TargetObject.RequestUri\r\n            ScriptStackTrace      = $ErrorObject.ScriptStackTrace\r\n            ErrorMessage          = ''\r\n        }\r\n        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') {\r\n            $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message\r\n        }\r\n        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {\r\n            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()\r\n        }\r\n        Write-Output $httpErrorObj\r\n    }\r\n}\r\nfunction Resolve-AFASErrorMessage {\r\n    [CmdletBinding()]\r\n    param (\r\n        [Parameter(ValueFromPipeline)]\r\n        [object]$ErrorObject\r\n    )\r\n    process {\r\n        try {\r\n            $errorObjectConverted = $ErrorObject | ConvertFrom-Json -ErrorAction Stop\r\n\r\n            if ($null -ne $errorObjectConverted.externalMessage) {\r\n                $errorMessage = $errorObjectConverted.externalMessage\r\n            }\r\n            else {\r\n                $errorMessage = $errorObjectConverted\r\n            }\r\n        }\r\n        catch {\r\n            $errorMessage = \"$($ErrorObject.Exception.Message)\"\r\n        }\r\n\r\n        Write-Output $errorMessage\r\n    }\r\n}\r\n\r\nif (-not([string]::IsNullOrEmpty($employeeID))) {\r\n    # Used to connect to AFAS API endpoints\r\n    $BaseUri = $AFASBaseUrl\r\n    $Token = $AFASToken\r\n    $getConnector = \"T4E_HelloID_Users_v2\"\r\n    $updateConnector = \"KnEmployee\"\r\n\r\n    #Change mapping here\r\n    $account = [PSCustomObject]@{\r\n        'AfasEmployee' = @{\r\n            'Element' = @{\r\n                'Objects' = @(\r\n                    @{\r\n                        'KnPerson' = @{\r\n                            'Element' = @{\r\n                                'Fields' = @{\r\n                                    # E-Mail werk  \r\n                                    'EmAd' = $newMail                   \r\n                                }\r\n                            }\r\n                        }\r\n                    }\r\n                )\r\n            }\r\n        }\r\n    }\r\n\r\n    $filterfieldid = \"Medewerker\"\r\n    $filtervalue = $employeeID # Has to match the AFAS value of the specified filter field ($filterfieldid)\r\n\r\n    # Get current AFAS employee and verify if a user must be either [created], [updated and correlated] or just [correlated]\r\n    try {\r\n        Write-Verbose \"Querying AFAS employee with $($filterfieldid) $($filtervalue)\"\r\n\r\n        # Create authorization headers\r\n        $encodedToken = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($Token))\r\n        $authValue = \"AfasToken $encodedToken\"\r\n        $Headers = @{ Authorization = $authValue }\r\n\r\n        $splatWebRequest = @{\r\n            Uri             = $BaseUri + \"/connectors/\" + $getConnector + \"?filterfieldids=$filterfieldid&filtervalues=$filtervalue&operatortypes=1\"\r\n            Headers         = $headers\r\n            Method          = 'GET'\r\n            ContentType     = \"application/json;charset=utf-8\"\r\n            UseBasicParsing = $true\r\n        }        \r\n        $currentAccount = (Invoke-RestMethod @splatWebRequest -Verbose:$false).rows\r\n\r\n        if ($null -eq $currentAccount.Medewerker) {\r\n            throw \"No AFAS employee found with $($filterfieldid) $($filtervalue)\"\r\n        }\r\n        Write-Information \"Found AFAS employee [$($currentAccount.Medewerker)]\"\r\n        # Check if current EmAd has a different value from mapped value. AFAS will throw an error when trying to update this with the same value\r\n        if ([string]$currentAccount.Email_werk -ne $account.'AfasEmployee'.'Element'.Objects[0].'KnPerson'.'Element'.'Fields'.'EmAd' -and $null -ne $account.'AfasEmployee'.'Element'.Objects[0].'KnPerson'.'Element'.'Fields'.'EmAd') {\r\n            $propertiesChanged += @('EmAd')\r\n        }\r\n        if ($propertiesChanged) {\r\n            Write-Verbose \"Account property(s) required to update: [$($propertiesChanged -join \",\")]\"\r\n            $updateAction = 'Update'\r\n        }\r\n        else {\r\n            $updateAction = 'NoChanges'\r\n        }\r\n\r\n        # Update AFAS Employee\r\n        Write-Verbose \"Start updating AFAS employee [$($currentAccount.Medewerker)]\"\r\n        switch ($updateAction) {\r\n            'Update' {\r\n                # Create custom account object for update\r\n                $updateAccount = [PSCustomObject]@{\r\n                    'AfasEmployee' = @{\r\n                        'Element' = @{\r\n                            '@EmId'   = $currentAccount.Medewerker\r\n                            'Objects' = @(@{\r\n                                    'KnPerson' = @{\r\n                                        'Element' = @{\r\n                                            'Fields' = @{\r\n                                                # Zoek op BcCo (Persoons-ID)\r\n                                                'MatchPer' = 0\r\n                                                # Nummer\r\n                                                'BcCo'     = $currentAccount.Persoonsnummer\r\n                                            }\r\n                                        }\r\n                                    }\r\n                                })\r\n                        }\r\n                    }\r\n                }\r\n                if ('EmAd' -in $propertiesChanged) {\r\n                    # E-mail werk\r\n                    $updateAccount.'AfasEmployee'.'Element'.Objects[0].'KnPerson'.'Element'.'Fields'.'EmAd' = $account.'AfasEmployee'.'Element'.Objects[0].'KnPerson'.'Element'.'Fields'.'EmAd'\r\n                    Write-Information \"Updating BusinessEmailAddress '$($currentAccount.Email_werk)' with new value '$($updateAccount.'AfasEmployee'.'Element'.Objects[0].'KnPerson'.'Element'.'Fields'.'EmAd')'\"\r\n                }\r\n\r\n                $body = ($updateAccount | ConvertTo-Json -Depth 10)\r\n                $splatWebRequest = @{\r\n                    Uri             = $BaseUri + \"/connectors/\" + $updateConnector\r\n                    Headers         = $headers\r\n                    Method          = 'PUT'\r\n                    Body            = ([System.Text.Encoding]::UTF8.GetBytes($body))\r\n                    ContentType     = \"application/json;charset=utf-8\"\r\n                    UseBasicParsing = $true\r\n                }\r\n\r\n                $updatedAccount = Invoke-RestMethod @splatWebRequest -Verbose:$false\r\n                Write-Information \"Successfully updated attribute [EmAd] of AFAS employee [$employeeID] from [$($currentAccount.Email_werk)] to [$newMail]\"\r\n                $Log = @{\r\n                    Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n                    System            = \"AFAS Employee\" # optional (free format text) \r\n                    Message           = \"Successfully updated attribute [EmAd] of AFAS employee [$employeeID] from [$($currentAccount.Email_werk)] to [$newMail]\" # required (free format text) \r\n                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                    TargetDisplayName = $displayName # optional (free format text) \r\n                    TargetIdentifier  = $([string]$employeeID) # optional (free format text) \r\n                }\r\n                #send result back  \r\n                Write-Information -Tags \"Audit\" -MessageData $log  \r\n                break\r\n            }\r\n            'NoChanges' {\r\n                Write-Information \"Successfully checked attribute [EmAd] of AFAS employee [$employeeID] from [$($currentAccount.Email_werk)] to [$newMail], no changes needed\"\r\n                $Log = @{\r\n                    Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n                    System            = \"AFAS Employee\" # optional (free format text) \r\n                    Message           = \"Successfully checked attribute [EmAd] of AFAS employee [$employeeID] from [$($currentAccount.Email_werk)] to [$newMail], no changes needed\" # required (free format text) \r\n                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                    TargetDisplayName = $displayName # optional (free format text) \r\n                    TargetIdentifier  = $([string]$employeeID) # optional (free format text) \r\n                }\r\n                #send result back  \r\n                Write-Information -Tags \"Audit\" -MessageData $log  \r\n                break\r\n            }\r\n        }\r\n    }\r\n    catch {\r\n        $ex = $PSItem\r\n        if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {\r\n            $errorObject = Resolve-HTTPError -Error $ex\r\n\r\n            $verboseErrorMessage = $errorObject.ErrorMessage\r\n\r\n            $auditErrorMessage = Resolve-AFASErrorMessage -ErrorObject $errorObject.ErrorMessage\r\n        }\r\n\r\n        # If error message empty, fall back on $ex.Exception.Message\r\n        if ([String]::IsNullOrEmpty($verboseErrorMessage)) {\r\n            $verboseErrorMessage = $ex.Exception.Message\r\n        }\r\n        if ([String]::IsNullOrEmpty($auditErrorMessage)) {\r\n            $auditErrorMessage = $ex.Exception.Message\r\n        }\r\n\r\n        $ex = $PSItem\r\n        $verboseErrorMessage = $ex\r\n        if ($auditErrorMessage -Like \"No AFAS employee found with $($filterfieldid) $($filtervalue)\") {\r\n            Write-Information \"Skipped update attribute [EmAd] of AFAS employee [$employeeID] to [$newMail]: No AFAS employee found with $($filterfieldid) $($filtervalue)\"\r\n            $Log = @{\r\n                Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n                System            = \"AFAS Employee\" # optional (free format text) \r\n                Message           = \"Skipped update attribute [EmAd] of AFAS employee [$employeeID] to [$newMail]: No AFAS employee found with $($filterfieldid) $($filtervalue)\" # required (free format text) \r\n                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                TargetDisplayName = $displayName # optional (free format text) \r\n                TargetIdentifier  = $([string]$employeeID) # optional (free format text)\r\n            }\r\n            #send result back  \r\n            Write-Information -Tags \"Audit\" -MessageData $log \r\n        }\r\n        else {\r\n            Write-Verbose \"Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)\"\r\n            Write-Error \"Error updating AFAS employee $($currentAccount.Medewerker). Error Message: $auditErrorMessage\"\r\n            Write-Information \"Error updating AFAS employee $($currentAccount.Medewerker). Error Message: $auditErrorMessage\"\r\n            $Log = @{\r\n                Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n                System            = \"AFAS Employee\" # optional (free format text) \r\n                Message           = \"Error updating AFAS employee $($currentAccount.Medewerker). Error Message: $auditErrorMessage\" # required (free format text) \r\n                IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                TargetDisplayName = $displayName # optional (free format text) \r\n                TargetIdentifier  = $([string]$employeeID) # optional (free format text) \r\n            }\r\n            #send result back  \r\n            Write-Information -Tags \"Audit\" -MessageData $log \r\n        }\r\n    }\r\n}\r\nelse {\r\n    Write-Information \"Skipped update attribute [EmAd] of AFAS employee [$displayName] to [$newMail]: employeeID is empty\"\r\n    $Log = @{\r\n        Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n        System            = \"AFAS Employee\" # optional (free format text) \r\n        Message           = \"Skipped update attribute [EmAd] of AFAS employee [$displayName] to [$newMail]: employeeID is empty\" # required (free format text) \r\n        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n        TargetDisplayName = $displayName # optional (free format text) \r\n        TargetIdentifier  = $([string]$employeeID) # optional (free format text)\r\n    }\r\n    #send result back  \r\n    Write-Information -Tags \"Audit\" -MessageData $log \r\n}\r\n#endregion AFAS","runInCloud":true}
'@ 

Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-envelope" -task $tmpTask -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

