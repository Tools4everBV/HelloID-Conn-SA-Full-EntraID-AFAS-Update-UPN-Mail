# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#HelloID variables
#Note: when running this script inside HelloID; portalUrl and API credentials are provided automatically (generate and save API credentials first in your admin panel!)
$portalUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("") #Only unique names are supported. Groups must exist!
$delegatedFormCategories = @("User Management","Entra ID") #Only unique names are supported. Categories will be created if not exists
$script:debugLogging = $false #Default value: $false. If $true, the HelloID resource GUIDs will be shown in the logging
$script:duplicateForm = $false #Default value: $false. If $true, the HelloID resource names will be changed to import a duplicate Form
$script:duplicateFormSuffix = "_tmp" #the suffix will be added to all HelloID resource names to generate a duplicate form with different resource names

#The following HelloID Global variables are used by this form. No existing HelloID global variables will be overriden only new ones are created.
#NOTE: You can also update the HelloID Global variable values afterwards in the HelloID Admin Portal: https://<CUSTOMER>.helloid.com/admin/variablelibrary
$globalHelloIDVariables = [System.Collections.Generic.List[object]]@();

#Global variable #1 >> EntraIdCertificatePassword
$tmpName = @'
EntraIdCertificatePassword
'@ 
$tmpValue = @'
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "True"});

#Global variable #2 >> EntraIdCertificateBase64String
$tmpName = @'
EntraIdCertificateBase64String
'@ 
$tmpValue = @'
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "True"});

#Global variable #3 >> EntraIdTenantId
$tmpName = @'
EntraIdTenantId
'@ 
$tmpValue = @'
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #4 >> AFASToken
$tmpName = @'
AFASToken
'@ 
$tmpValue = @'
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "True"});

#Global variable #5 >> AFASBaseUrl
$tmpName = @'
AFASBaseUrl
'@ 
$tmpValue = @'
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #6 >> EntraIdAppId
$tmpName = @'
EntraIdAppId
'@ 
$tmpValue = @'
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
        [parameter()][String][AllowEmptyString()]$DatasourceRunInCloud,
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
                runInCloud         = $DatasourceRunInCloud;
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
<# Begin: DataSource "entra-id-afas-account-update-upn-email | Entra-ID-Uniqueness-Validation" #>
$tmpPsScript = @'
#######################################################################
# Template: HelloID SA Powershell data source
# Name:     entra-id-afas-account-update-upn-email | Entra-ID-Uniqueness-Validation
# Date:     18-02-2026
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

# global variables (Automation --> Variable library):
$TenantId = $EntraIdTenantId
$AppId = $EntraIdAppId
$CertificateBase64String = $EntraIdCertificateBase64String
$CertificatePassword = $EntraIdCertificatePassword

# variables configured in form:
$userId = $dataSource.gridUsers.Id
$mailCurrent = $dataSource.gridUsers.Mail
$upnCurrent = $dataSource.gridUsers.userPrincipalName

$changeMail = [System.Convert]::ToBoolean($dataSource.blnMail)
$mailNew = $dataSource.NewMail
$changeUpn = [System.Convert]::ToBoolean($dataSource.blnUPN)
$upnNew = $dataSource.NewUPN

#endregion init

#region functions
function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
    )
    try {
        # Get the DER encoded bytes of the certificate
        $derBytes = $Certificate.RawData

        # Compute the SHA-256 hash of the DER encoded bytes
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        # Create a JWT (JSON Web Token) header
        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        # Calculate the Unix timestamp (seconds since 1970-01-01T00:00:00Z) for 'exp', 'nbf' and 'iat'
        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        # Create a JWT payload
        $payload = [Ordered]@{
            'iss' = "$AppId"
            'sub' = "$AppId"
            'aud' = "https://login.microsoftonline.com/$TenantId/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600) # Expires in 1 hour
            'nbf' = ($currentUnixTimestamp - 300) # Not before 5 minutes ago
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        # Extract the private key from the certificate
        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        # Sign the JWT
        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')
	
        # Extract the private key from the certificate
        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
            throw "The certificate does not have a private key."
        }

        # Create the JWT token
        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $AppId
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$TenantId/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        Write-Output $createEntraAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($CertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $CertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
function Resolve-MicrosoftGraphAPIError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json -ErrorAction Stop)
            if ($errorDetailsObject.error_description) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description
            }
            elseif ($errorDetailsObject.error.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.code): $($errorDetailsObject.error.message)"
            }
            elseif ($errorDetailsObject.error.details.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.details.code): $($errorDetailsObject.error.details.message)"
            }
            else {
                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}
#endregion functions

#region lookup
try {
    $actionMessage = "validating new UPN and mail values"
    Write-Information "Validating new UPN and mail values"

    if (-not ($changeMail -or $changeUpn)) {
        $outputText.Add([PSCustomObject]@{
                Message  = "Neither UPN nor mail change selected"
                IsError  = $true
                Property = "UPN/mail"
            })
    }

    if ($changeUpn -and ([string]::IsNullOrWhiteSpace($upnNew) -or ($upnCurrent -eq $upnNew))) {
        $outputText.Add([PSCustomObject]@{
                Message  = "UPN [$upnCurrent] not changed or empty"
                IsError  = $true
                Property = "UPN"
            })
    }

    if ($changeMail -and ([string]::IsNullOrWhiteSpace($mailNew) -or ($mailCurrent -eq $mailNew))) {
        $outputText.Add([PSCustomObject]@{
                Message  = "mail [$mailCurrent] not changed or empty"
                IsError  = $true
                Property = "mail"
            })
    }
    
    if (-not($outputText.isError -contains - $true)) {
        $actionMessage = "checking Entra ID for uniqueness"

        # Setup Connection with Entra/Exo
        Write-Information 'Checking Entra ID for uniqueness, connecting to MS-Entra'
        $certificate = Get-MSEntraCertificate
        $entraToken = Get-MSEntraAccessToken -Certificate $certificate
    
        #Add the authorization header to the request
        $authorization = @{
            Authorization  = "Bearer $entraToken";
            'Content-Type' = "application/json";
            Accept         = "application/json";
        } 

        $graphApiUrl = "https://graph.microsoft.com/v1.0/users"
        $select = '&$select=id,displayName,userPrincipalName,mail,proxyAddresses' + '&$top=999'
        
        # Build filter dynamically based on what's being changed
        $filterConditions = [System.Collections.Generic.List[string]]::new()
        if ($changeUpn) {
            $filterConditions.Add("userPrincipalName eq '$upnNew'")
            $filterConditions.Add("proxyAddresses/any(p:p eq '$upnNew')")
        }
        if ($changeMail) {
            $filterConditions.Add("mail eq '$mailNew'")
            $filterConditions.Add("proxyAddresses/any(p:p eq '$mailNew')")
        }
        
        $filter = $filterConditions -join ' or '
        $searchUri = $graphApiUrl + '?$filter=' + $filter + $select

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

        
        Write-Warning "user: [$($entraIDUsers | ConvertTo-Json)]"

        # Filter out the user that will be updated
        $filteredEntraIDUsers = $entraIDUsers | Where-Object { $_.id -ne $userId }

        Write-Warning "filteredUsers: [$($filteredEntraIDUsers | ConvertTo-Json)]"

        foreach ($record in $filteredEntraIDUsers) {
            if ($record.userPrincipalName -eq $upnNew -and $changeUpn) {
                $outputText.Add([PSCustomObject]@{
                        Message  = "UPN [$upnNew] not unique, found on [$($record.displayName)]"
                        IsError  = $true
                        Property = "UPN"
                    })
            }
            if ($record.mail -eq $mailNew -and $changeMail) {
                $outputText.Add([PSCustomObject]@{
                        Message  = "mail [$mailNew] not unique, found on [$($record.displayName)]"
                        IsError  = $true
                        Property = "mail"
                    })
            }
            if ((($record.proxyAddresses -eq "SMTP:$mailNew") -or ($record.proxyAddresses -eq "smtp:$mailNew")) -and $changeMail) {
                $outputText.Add([PSCustomObject]@{
                        Message  = "ProxyAddress [$mailNew] not unique, found on [$($record.displayName)]"
                        IsError  = $true
                        Property = "proxyAddresses"
                    })
            }
            if ((($record.proxyAddresses -eq "SMTP:$upnNew") -or ($record.proxyAddresses -eq "smtp:$upnNew")) -and $changeUpn) {
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
        if ($changeUpn) {
            $outputText.Add([PSCustomObject]@{
                    Message  = "UPN [$upnNew] unique"
                    IsError  = $false
                    Property = "UPN"
                })
        }
        if ($changeMail) {
            $outputText.Add([PSCustomObject]@{
                    Message  = "mail [$mailNew] unique"
                    IsError  = $false
                    Property = "mail"
                })
        }
    }

    foreach ($text in $outputText) {
        $outputMessage += " | " + $($text.Message)
    }

    $returnObject = @{
        text              = $outputMessage
        userPrincipalName = $upnNew
        mail              = $mailNew
    }

    Write-Output $returnObject      
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    Write-Warning $warningMessage
    Write-Error $auditMessage
}  
#endregion lookup

'@ 
$tmpModel = @'
[{"key":"mail","type":0},{"key":"text","type":0},{"key":"userPrincipalName","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"gridUsers","type":0,"options":1},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"blnMail","type":0,"options":0},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"NewMail","type":0,"options":0},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"blnUPN","type":0,"options":0},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"NewUPN","type":0,"options":0}]
'@ 
$dataSourceGuid_1 = [PSCustomObject]@{} 
$dataSourceGuid_1_Name = @'
entra-id-afas-account-update-upn-email | Entra-ID-Uniqueness-Validation
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_1_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -DataSourceRunInCloud "True" -returnObject ([Ref]$dataSourceGuid_1) 
<# End: DataSource "entra-id-afas-account-update-upn-email | Entra-ID-Uniqueness-Validation" #>

<# Begin: DataSource "entra-id-afas-account-update-upn-email | Entra-ID-Get-Active-Users-DisplayName-Mail-Upn" #>
$tmpPsScript = @'
#######################################################################
# Template: HelloID SA Powershell data source
# Name:     EntraId-Get-Active-Users-DisplayName-Mail-Name-UserprincipalName
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

# global variables (Automation --> Variable library):
$TenantId = $EntraIdTenantId
$AppId = $EntraIdAppId
$CertificateBase64String = $EntraIdCertificateBase64String
$CertificatePassword = $EntraIdCertificatePassword

# variables configured in form:
$searchValue = $dataSource.searchUser
$searchQuery = "*$searchValue*"

#endregion init

#region functions
function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
    )
    try {
        # Get the DER encoded bytes of the certificate
        $derBytes = $Certificate.RawData

        # Compute the SHA-256 hash of the DER encoded bytes
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        # Create a JWT (JSON Web Token) header
        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        # Calculate the Unix timestamp (seconds since 1970-01-01T00:00:00Z) for 'exp', 'nbf' and 'iat'
        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        # Create a JWT payload
        $payload = [Ordered]@{
            'iss' = "$AppId"
            'sub' = "$AppId"
            'aud' = "https://login.microsoftonline.com/$TenantId/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600) # Expires in 1 hour
            'nbf' = ($currentUnixTimestamp - 300) # Not before 5 minutes ago
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        # Extract the private key from the certificate
        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        # Sign the JWT
        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')
	
        # Extract the private key from the certificate
        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
            throw "The certificate does not have a private key."
        }

        # Create the JWT token
        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $AppId
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$TenantId/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        Write-Output $createEntraAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($CertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $CertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
function Resolve-MicrosoftGraphAPIError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json -ErrorAction Stop)
            if ($errorDetailsObject.error_description) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description
            }
            elseif ($errorDetailsObject.error.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.code): $($errorDetailsObject.error.message)"
            }
            elseif ($errorDetailsObject.error.details.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.details.code): $($errorDetailsObject.error.details.message)"
            }
            else {
                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}
#endregion functions

#region lookup
try {      
    # Setup Connection with Entra/Exo
    Write-Information 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate
    
    #Add the authorization header to the request
    $authorization = @{
        Authorization  = "Bearer $entraToken";
        'Content-Type' = "application/json";
        Accept         = "application/json";
    } 

    $actionMessage = "searching for Entra ID users"
    Write-Information "Searching for: $searchQuery"
    
    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/users" + '?$select=Id,userPrincipalName,displayName,EmployeeID,mail' + '&$top=999'

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
            $returnObject = @{
                DisplayName       = $user.DisplayName
                UserPrincipalName = $user.UserPrincipalName
                Mail              = $user.mail
                Id                = $user.Id
                EmployeeID        = $user.EmployeeID
            }    
            Write-Output $returnObject      
        }
    }
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    Write-Warning $warningMessage
    Write-Error $auditMessage
}
#endregion lookup

'@ 
$tmpModel = @'
[{"key":"Id","type":0},{"key":"Mail","type":0},{"key":"EmployeeID","type":0},{"key":"DisplayName","type":0},{"key":"UserPrincipalName","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"searchUser","type":0,"options":1}]
'@ 
$dataSourceGuid_0 = [PSCustomObject]@{} 
$dataSourceGuid_0_Name = @'
entra-id-afas-account-update-upn-email | Entra-ID-Get-Active-Users-DisplayName-Mail-Upn
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_0_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -DataSourceRunInCloud "True" -returnObject ([Ref]$dataSourceGuid_0) 
<# End: DataSource "entra-id-afas-account-update-upn-email | Entra-ID-Get-Active-Users-DisplayName-Mail-Upn" #>
<# End: HelloID Data sources #>

<# Begin: Dynamic Form "Entra ID AFAS Account - Update UPN - Email" #>
$tmpSchema = @"
[{"label":"Select user account","fields":[{"key":"searchfield","templateOptions":{"label":"Search","placeholder":"Username or Email"},"type":"input","summaryVisibility":"Hide element","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"gridUsers","templateOptions":{"label":"Select user account","required":true,"grid":{"columns":[{"headerName":"Employee ID","field":"EmployeeID"},{"headerName":"Display Name","field":"DisplayName"},{"headerName":"Mail","field":"Mail"},{"headerName":"User Principal Name","field":"UserPrincipalName"},{"headerName":"Id","field":"Id"}],"height":300,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[{"propertyName":"searchUser","otherFieldValue":{"otherFieldKey":"searchfield"}}]}},"useFilter":true,"useDefault":false,"searchPlaceHolder":"Search this data","allowCsvDownload":false},"type":"grid","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":true}]},{"label":"Details","fields":[{"key":"blnMail","templateOptions":{"label":"Update Email","useSwitch":true,"checkboxLabel":""},"type":"boolean","defaultValue":false,"summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"formRowMail","templateOptions":{},"fieldGroup":[{"key":"CurrentMail","templateOptions":{"label":"Current Email Address","useDataSource":false,"useDependOn":true,"dependOn":"gridUsers","dependOnProperty":"Mail","readonly":true},"hideExpression":"!model[\"blnMail\"]","type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"NewMail","templateOptions":{"label":"New Email Address","useDependOn":true,"dependOn":"gridUsers","dependOnProperty":"Mail","pattern":"^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$"},"validation":{"messages":{"pattern":"The entered value is not a valid email format."}},"hideExpression":"!model[\"blnMail\"]","type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false}],"type":"formrow","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"blnUPN","templateOptions":{"label":"Update user principal name","useSwitch":true,"checkboxLabel":""},"type":"boolean","defaultValue":false,"summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"formRowUPN","templateOptions":{},"fieldGroup":[{"key":"CurrentUPN","templateOptions":{"label":"Current user principal name","useDependOn":true,"dependOn":"gridUsers","dependOnProperty":"UserPrincipalName","readonly":true},"hideExpression":"!model[\"blnUPN\"]","type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"NewUPN","templateOptions":{"label":"New user principal name","useDependOn":true,"dependOn":"gridUsers","dependOnProperty":"UserPrincipalName","pattern":"^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$"},"validation":{"messages":{"pattern":"The entered value is not a valid UPN format."}},"hideExpression":"!model[\"blnUPN\"]","type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false}],"type":"formrow","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"validate","templateOptions":{"label":"Validation","readonly":true,"useDataSource":true,"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_1","input":{"propertyInputs":[{"propertyName":"gridUsers","otherFieldValue":{"otherFieldKey":"gridUsers"}},{"propertyName":"blnMail","otherFieldValue":{"otherFieldKey":"blnMail"}},{"propertyName":"NewMail","otherFieldValue":{"otherFieldKey":"NewMail"}},{"propertyName":"blnUPN","otherFieldValue":{"otherFieldKey":"blnUPN"}},{"propertyName":"NewUPN","otherFieldValue":{"otherFieldKey":"NewUPN"}}]}},"displayField":"text","minLength":1,"pattern":"^Valid.*","required":true},"validation":{"messages":{"pattern":"No valid value"}},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false}]}]
"@ 

$dynamicFormGuid = [PSCustomObject]@{} 
$dynamicFormName = @'
Entra ID AFAS Account - Update UPN - Email
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
Entra ID AFAS Account - Update UPN - Email
'@
$tmpTask = @'
{"name":"Entra ID AFAS Account - Update UPN - Email","script":"#######################################################################\n# Template: HelloID SA Delegated form task\n# Name:     EntraID-account-update-upn-mail\n# Date:     18-02-2026\n#######################################################################\n\n# For basic information about delegated form tasks see:\n# https://docs.helloid.com/en/service-automation/delegated-forms/delegated-form-powershell-scripts/add-a-powershell-script-to-a-delegated-form.html\n\n# Service automation variables:\n# https://docs.helloid.com/en/service-automation/service-automation-variables/service-automation-variable-reference.html\n\n#region init\n\n$VerbosePreference = \"SilentlyContinue\"\n$InformationPreference = \"Continue\"\n$WarningPreference = \"Continue\"\n\n# global variables (Automation --\u003e Variable library):\n# Entra ID\n$TenantId = $EntraIdTenantId\n$AppId = $EntraIdAppId\n$CertificateBase64String = $EntraIdCertificateBase64String\n$CertificatePassword = $EntraIdCertificatePassword\n\n# AFAS\n$BaseUrl = $AFASBaseUrl\n$Token = $AFASToken\n\n# variables configured in form:\n$entraidGUID = $form.gridUsers.Id\n$displayName = $form.gridUsers.DisplayName\n$employeeID = $form.gridUsers.employeeID\n\n$currentUPN = $form.gridUsers.UserPrincipalName\n$changeUpn = [System.Convert]::ToBoolean($form.blnUPN)\n$newUPN = $form.NewUPN\n\n$currentMail = $form.gridUsers.Mail\n$changeMail = [System.Convert]::ToBoolean($form.blnMail)\n$newMail = $form.NewMail\n\n#endregion init\n\n#region Entra ID functions\nfunction Get-MSEntraAccessToken {\n    [CmdletBinding()]\n    param(\n        [Parameter(Mandatory)]\n        $Certificate\n    )\n    try {\n        # Get the DER encoded bytes of the certificate\n        $derBytes = $Certificate.RawData\n\n        # Compute the SHA-256 hash of the DER encoded bytes\n        $sha256 = [System.Security.Cryptography.SHA256]::Create()\n        $hashBytes = $sha256.ComputeHash($derBytes)\n        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace(\u0027+\u0027, \u0027-\u0027).Replace(\u0027/\u0027, \u0027_\u0027).Replace(\u0027=\u0027, \u0027\u0027)\n\n        # Create a JWT (JSON Web Token) header\n        $header = @{\n            \u0027alg\u0027      = \u0027RS256\u0027\n            \u0027typ\u0027      = \u0027JWT\u0027\n            \u0027x5t#S256\u0027 = $base64Thumbprint\n        } | ConvertTo-Json\n        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))\n\n        # Calculate the Unix timestamp (seconds since 1970-01-01T00:00:00Z) for \u0027exp\u0027, \u0027nbf\u0027 and \u0027iat\u0027\n        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]\u00271970-01-01T00:00:00Z\u0027).ToUniversalTime()).TotalSeconds)\n\n        # Create a JWT payload\n        $payload = [Ordered]@{\n            \u0027iss\u0027 = \"$AppId\"\n            \u0027sub\u0027 = \"$AppId\"\n            \u0027aud\u0027 = \"https://login.microsoftonline.com/$TenantId/oauth2/token\"\n            \u0027exp\u0027 = ($currentUnixTimestamp + 3600) # Expires in 1 hour\n            \u0027nbf\u0027 = ($currentUnixTimestamp - 300) # Not before 5 minutes ago\n            \u0027iat\u0027 = $currentUnixTimestamp\n            \u0027jti\u0027 = [Guid]::NewGuid().ToString()\n        } | ConvertTo-Json\n        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace(\u0027+\u0027, \u0027-\u0027).Replace(\u0027/\u0027, \u0027_\u0027).Replace(\u0027=\u0027, \u0027\u0027)\n\n        # Extract the private key from the certificate\n        $rsaPrivate = $Certificate.PrivateKey\n        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()\n        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))\n\n        # Sign the JWT\n        $signatureInput = \"$base64Header.$base64Payload\"\n        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), \u0027SHA256\u0027)\n        $base64Signature = [System.Convert]::ToBase64String($signature).Replace(\u0027+\u0027, \u0027-\u0027).Replace(\u0027/\u0027, \u0027_\u0027).Replace(\u0027=\u0027, \u0027\u0027)\n\t\n        # Extract the private key from the certificate\n        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {\n            throw \"The certificate does not have a private key.\"\n        }\n\n        # Create the JWT token\n        $jwtToken = \"$($base64Header).$($base64Payload).$($base64Signature)\"\n\n        $createEntraAccessTokenBody = @{\n            grant_type            = \u0027client_credentials\u0027\n            client_id             = $AppId\n            client_assertion_type = \u0027urn:ietf:params:oauth:client-assertion-type:jwt-bearer\u0027\n            client_assertion      = $jwtToken\n            resource              = \u0027https://graph.microsoft.com\u0027\n        }\n\n        $createEntraAccessTokenSplatParams = @{\n            Uri         = \"https://login.microsoftonline.com/$TenantId/oauth2/token\"\n            Body        = $createEntraAccessTokenBody\n            Method      = \u0027POST\u0027\n            ContentType = \u0027application/x-www-form-urlencoded\u0027\n            Verbose     = $false\n            ErrorAction = \u0027Stop\u0027\n        }\n\n        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams\n        Write-Output $createEntraAccessTokenResponse.access_token\n    }\n    catch {\n        $PSCmdlet.ThrowTerminatingError($_)\n    }\n}\n\nfunction Get-MSEntraCertificate {\n    [CmdletBinding()]\n    param()\n    try {\n        $rawCertificate = [system.convert]::FromBase64String($CertificateBase64String)\n        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $CertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)\n        Write-Output $certificate\n    }\n    catch {\n        $PSCmdlet.ThrowTerminatingError($_)\n    }\n}\nfunction Resolve-MicrosoftGraphAPIError {\n    [CmdletBinding()]\n    param (\n        [Parameter(Mandatory)]\n        [object]\n        $ErrorObject\n    )\n    process {\n        $httpErrorObj = [PSCustomObject]@{\n            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber\n            Line             = $ErrorObject.InvocationInfo.Line\n            ErrorDetails     = $ErrorObject.Exception.Message\n            FriendlyMessage  = $ErrorObject.Exception.Message\n        }\n        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {\n            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message\n        }\n        elseif ($ErrorObject.Exception.GetType().FullName -eq \u0027System.Net.WebException\u0027) {\n            if ($null -ne $ErrorObject.Exception.Response) {\n                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()\n                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {\n                    $httpErrorObj.ErrorDetails = $streamReaderResponse\n                }\n            }\n        }\n        try {\n            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json -ErrorAction Stop)\n            if ($errorDetailsObject.error_description) {\n                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description\n            }\n            elseif ($errorDetailsObject.error.message) {\n                $httpErrorObj.FriendlyMessage = \"$($errorDetailsObject.error.code): $($errorDetailsObject.error.message)\"\n            }\n            elseif ($errorDetailsObject.error.details.message) {\n                $httpErrorObj.FriendlyMessage = \"$($errorDetailsObject.error.details.code): $($errorDetailsObject.error.details.message)\"\n            }\n            else {\n                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails\n            }\n        }\n        catch {\n            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails\n        }\n        Write-Output $httpErrorObj\n    }\n}\n#endregion Entra ID functions\n\n#region EntraID\ntry {\n    $actionMessage = \"updating Entra ID user\"\n    \n    # Build account object dynamically based on what should be changed\n    $account = [PSCustomObject]@{}\n    \n    if ($changeUpn) {\n        $account | Add-Member -MemberType NoteProperty -Name \u0027userPrincipalName\u0027 -Value $newUPN\n    }\n    \n    if ($changeMail) {\n        $account | Add-Member -MemberType NoteProperty -Name \u0027mail\u0027 -Value $newMail\n    }\n\n    # Setup Connection with Entra/Exo\n    Write-Verbose \u0027connecting to MS-Entra\u0027\n    $certificate = Get-MSEntraCertificate\n    $entraToken = Get-MSEntraAccessToken -Certificate $certificate\n    #Add the authorization header to the request\n    $authorization = @{\n        Authorization  = \"Bearer $entraToken\";\n        \u0027Content-Type\u0027 = \"application/json\";\n        Accept         = \"application/json\";\n    }\n \n    $baseUpdateUri = \"https://graph.microsoft.com/\"\n    $updateUri = $baseUpdateUri + \"v1.0/users/$($entraidGUID)\"\n    $body = $account | ConvertTo-Json -Depth 10\n\n    $response = Invoke-RestMethod -Uri $updateUri -Method PATCH -Headers $authorization -Body $body -Verbose:$false\n    \n    # Build success message based on what was changed\n    $changedAttributes = @()\n    if ($changeUpn) {\n        $changedAttributes += \"[userPrincipalName] from [$currentUPN] to [$newUPN]\"\n    }\n    if ($changeMail) {\n        $changedAttributes += \"[mail] from [$currentMail] to [$newMail]\"\n    }\n    $auditMessage = \"Successfully updated Entra ID user [$displayName] attributes $($changedAttributes -join \u0027 and \u0027)\"\n    Write-Information $auditMessage\n    $Log = @{\n        Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \n        System            = \"Entra ID\" # optional (free format text) \n        Message           = $auditMessage\n        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \n        TargetDisplayName = $displayName # optional (free format text) \n        TargetIdentifier  = $([string]$entraidGUID) # optional (free format text) \n    }\n    #send result back  \n    Write-Information -Tags \"Audit\" -MessageData $log    \n}\ncatch {\n    $ex = $PSItem\n    if ($($ex.Exception.GetType().FullName -eq \u0027Microsoft.PowerShell.Commands.HttpResponseException\u0027) -or\n        $($ex.Exception.GetType().FullName -eq \u0027System.Net.WebException\u0027)) {\n        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex\n        $auditMessage = \"Error $($actionMessage). Error: $($errorObj.FriendlyMessage)\"\n        $warningMessage = \"Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)\"\n    }\n    else {\n        $auditMessage = \"Error $($actionMessage). Error: $($ex.Exception.Message)\"\n        $warningMessage = \"Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)\"\n    }\n    $Log = @{\n        Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \n        System            = \"Entra ID\" # optional (free format text) \n        Message           = $auditMessage # required (free format text) \n        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \n        TargetDisplayName = $displayName # optional (free format text) \n        TargetIdentifier  = $([string]$entraidGUID) # optional (free format text) \n    }\n    Write-Information -Tags \"Audit\" -MessageData $log\n    Write-Warning $warningMessage\n    Write-Error $auditMessage\n}\n#endregion EntraID\n\n#region AFAS functions\nfunction Resolve-AFAS-ProfitError {\n    [CmdletBinding()]\n    param (\n        [Parameter(Mandatory)]\n        [object]\n        $ErrorObject\n    )\n    process {\n        $httpErrorObj = [PSCustomObject]@{\n            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber\n            Line             = $ErrorObject.InvocationInfo.Line\n            ErrorDetails     = $ErrorObject.Exception.Message\n            FriendlyMessage  = $ErrorObject.Exception.Message\n        }\n        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {\n            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message\n        }\n        elseif ($ErrorObject.Exception.GetType().FullName -eq \u0027System.Net.WebException\u0027) {\n            if ($null -ne $ErrorObject.Exception.Response) {\n                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()\n                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {\n                    $httpErrorObj.ErrorDetails = $streamReaderResponse\n                }\n            }\n        }\n        try {\n            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json)\n\n            if ($null -ne $errorDetailsObject.externalMessage) {\n                $httpErrorObj.FriendlyMessage = $errorDetailsObject.externalMessage\n            }\n            else {\n                $httpErrorObj.FriendlyMessage = $errorDetailsObject\n            }\n        }\n        catch {\n            $httpErrorObj.FriendlyMessage = \"[$($httpErrorObj.ErrorDetails)]\"\n        }\n        Write-Output $httpErrorObj\n    }\n}\n#endregion AFAS functions\n\n#region AFAS\n# Only update AFAS if mail is being changed and employeeID is present\nif ($changeMail -and -not([string]::IsNullOrEmpty($employeeID))) {\n    # Used to connect to AFAS API endpoints\n    $getConnector = \"T4E_HelloID_Users_v2\"\n    $updateConnector = \"KnEmployee\"\n\n    #Change mapping here\n    $account = [PSCustomObject]@{\n        \u0027AfasEmployee\u0027 = @{\n            \u0027Element\u0027 = @{\n                \u0027Objects\u0027 = @(\n                    @{\n                        \u0027KnPerson\u0027 = @{\n                            \u0027Element\u0027 = @{\n                                \u0027Fields\u0027 = @{\n                                    # E-Mail werk  \n                                    \u0027EmAd\u0027 = $newMail                   \n                                }\n                            }\n                        }\n                    }\n                )\n            }\n        }\n    }\n\n    $filterfieldid = \"Medewerker\"\n    $filtervalue = $employeeID # Has to match the AFAS value of the specified filter field ($filterfieldid)\n\n    # Get current AFAS employee and verify if a user must be either [created], [updated and correlated] or just [correlated]\n    try {\n        $actionMessage = \"querying AFAS employee\"\n        \n        Write-Information \"Querying AFAS employee with $($filterfieldid) $($filtervalue)\"\n\n        # Create authorization headers\n        $encodedToken = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($Token))\n        $authValue = \"AfasToken $encodedToken\"\n        $Headers = @{ Authorization = $authValue }\n\n        $splatWebRequest = @{\n            Uri             = $BaseUrl + \"/connectors/\" + $getConnector + \"?filterfieldids=$filterfieldid\u0026filtervalues=$filtervalue\u0026operatortypes=1\"\n            Headers         = $headers\n            Method          = \u0027GET\u0027\n            ContentType     = \"application/json;charset=utf-8\"\n            UseBasicParsing = $true\n        }        \n        $currentAccount = (Invoke-RestMethod @splatWebRequest -Verbose:$false).rows\n\n        if ($null -eq $currentAccount.Medewerker) {\n            throw \"No AFAS employee found with $($filterfieldid) $($filtervalue)\"\n        }\n        Write-Information \"Found AFAS employee [$($currentAccount.Medewerker)]\"\n        # Check if current EmAd has a different value from mapped value. AFAS will throw an error when trying to update this with the same value\n        if ([string]$currentAccount.Email_werk -ne $account.\u0027AfasEmployee\u0027.\u0027Element\u0027.Objects[0].\u0027KnPerson\u0027.\u0027Element\u0027.\u0027Fields\u0027.\u0027EmAd\u0027 -and $null -ne $account.\u0027AfasEmployee\u0027.\u0027Element\u0027.Objects[0].\u0027KnPerson\u0027.\u0027Element\u0027.\u0027Fields\u0027.\u0027EmAd\u0027) {\n            $propertiesChanged += @(\u0027EmAd\u0027)\n        }\n        if ($propertiesChanged) {\n            Write-Information \"Account property(s) required to update: [$($propertiesChanged -join \",\")]\"\n            $updateAction = \u0027Update\u0027\n        }\n        else {\n            $updateAction = \u0027NoChanges\u0027\n        }\n\n        # Update AFAS Employee\n        Write-Information \"Start updating AFAS employee [$($currentAccount.Medewerker)]\"\n        $actionMessage = \"updating AFAS employee\"\n        \n        switch ($updateAction) {\n            \u0027Update\u0027 {\n                # Create custom account object for update\n                $updateAccount = [PSCustomObject]@{\n                    \u0027AfasEmployee\u0027 = @{\n                        \u0027Element\u0027 = @{\n                            \u0027@EmId\u0027   = $currentAccount.Medewerker\n                            \u0027Objects\u0027 = @(@{\n                                    \u0027KnPerson\u0027 = @{\n                                        \u0027Element\u0027 = @{\n                                            \u0027Fields\u0027 = @{\n                                                # Zoek op BcCo (Persoons-ID)\n                                                \u0027MatchPer\u0027 = 0\n                                                # Nummer\n                                                \u0027BcCo\u0027     = $currentAccount.Persoonsnummer\n                                            }\n                                        }\n                                    }\n                                })\n                        }\n                    }\n                }\n                if (\u0027EmAd\u0027 -in $propertiesChanged) {\n                    # E-mail werk\n                    $updateAccount.\u0027AfasEmployee\u0027.\u0027Element\u0027.Objects[0].\u0027KnPerson\u0027.\u0027Element\u0027.\u0027Fields\u0027.\u0027EmAd\u0027 = $account.\u0027AfasEmployee\u0027.\u0027Element\u0027.Objects[0].\u0027KnPerson\u0027.\u0027Element\u0027.\u0027Fields\u0027.\u0027EmAd\u0027\n                    Write-Information \"Updating BusinessEmailAddress \u0027$($currentAccount.Email_werk)\u0027 with new value \u0027$($updateAccount.\u0027AfasEmployee\u0027.\u0027Element\u0027.Objects[0].\u0027KnPerson\u0027.\u0027Element\u0027.\u0027Fields\u0027.\u0027EmAd\u0027)\u0027\"\n                }\n\n                $body = ($updateAccount | ConvertTo-Json -Depth 10)\n                $splatWebRequest = @{\n                    Uri             = $BaseUrl + \"/connectors/\" + $updateConnector\n                    Headers         = $headers\n                    Method          = \u0027PUT\u0027\n                    Body            = ([System.Text.Encoding]::UTF8.GetBytes($body))\n                    ContentType     = \"application/json;charset=utf-8\"\n                    UseBasicParsing = $true\n                }\n\n                $updatedAccount = Invoke-RestMethod @splatWebRequest -Verbose:$false\n                $auditMessage = \"Successfully updated attribute [EmAd] of AFAS employee [$employeeID] from [$($currentAccount.Email_werk)] to [$newMail]\"\n                Write-Information $auditMessage\n                $Log = @{\n                    Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \n                    System            = \"AFAS Employee\" # optional (free format text) \n                    Message           = $auditMessage # required (free format text) \n                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \n                    TargetDisplayName = $displayName # optional (free format text) \n                    TargetIdentifier  = $([string]$employeeID) # optional (free format text) \n                }\n                #send result back  \n                Write-Information -Tags \"Audit\" -MessageData $log  \n                break\n            }\n            \u0027NoChanges\u0027 {\n                $auditMessage = \"Successfully checked attribute [EmAd] of AFAS employee [$employeeID] from [$($currentAccount.Email_werk)] to [$newMail], no changes needed\"\n                Write-Information $auditMessage\n                $Log = @{\n                    Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \n                    System            = \"AFAS Employee\" # optional (free format text) \n                    Message           = $auditMessage # required (free format text) \n                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \n                    TargetDisplayName = $displayName # optional (free format text) \n                    TargetIdentifier  = $([string]$employeeID) # optional (free format text) \n                }\n                #send result back  \n                Write-Information -Tags \"Audit\" -MessageData $log  \n                break\n            }\n        }\n    }\n    catch {\n        $ex = $PSItem\n        if ($($ex.Exception.GetType().FullName -eq \u0027Microsoft.PowerShell.Commands.HttpResponseException\u0027) -or\n            $($ex.Exception.GetType().FullName -eq \u0027System.Net.WebException\u0027)) {\n            $errorObj = Resolve-AFAS-ProfitError -ErrorObject $ex\n            $warningMessage = \"Error at Line \u0027$($errorObj.ScriptLineNumber)\u0027: $($errorObj.Line). Error: $($errorObj.ErrorDetails)\"\n            $auditMessage = \"Error $($actionMessage). Error: $($errorObj.FriendlyMessage)\"\n        }\n        else {\n            $warningMessage = \"Error at Line \u0027$($ex.InvocationInfo.ScriptLineNumber)\u0027: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)\"\n            $auditMessage = \"Error $($actionMessage). Error: $($ex.Exception.Message)\"\n        }\n        $log = @{\n            Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \n            System            = \"AFAS\" # optional (free format text) \n            Message           = $auditMessage # required (free format text) \n            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \n            TargetDisplayName = $displayName # optional (free format text) \n            TargetIdentifier  = $([string]$employeeID) # optional (free format text) \n        }\n        Write-Information -Tags \"Audit\" -MessageData $log\n        Write-Warning $warningMessage\n        Write-Error $auditMessage\n        # exit # use when using multiple try/catch and the script must stop\n    }\n}\nelse {\n    # Determine why AFAS update was skipped\n    if (-not $changeMail) {\n        $auditMessage = \"Skipped update attribute [EmAd] of AFAS employee [$displayName]: mail change not requested\"\n    }\n    elseif ([string]::IsNullOrEmpty($employeeID)) {\n        $auditMessage = \"Skipped update attribute [EmAd] of AFAS employee [$displayName] to [$newMail]: employeeID is empty\"\n    }\n    else {\n        $auditMessage = \"Skipped update attribute [EmAd] of AFAS employee [$displayName]\"\n    }\n    Write-Information $auditMessage\n    $Log = @{\n        Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \n        System            = \"AFAS Employee\" # optional (free format text) \n        Message           = $auditMessage # required (free format text) \n        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \n        TargetDisplayName = $displayName # optional (free format text) \n        TargetIdentifier  = $([string]$employeeID) # optional (free format text)\n    }\n    #send result back  \n    Write-Information -Tags \"Audit\" -MessageData $log \n}\n#endregion AFAS\n","runInCloud":true}
'@ 

Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-envelope" -task $tmpTask -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

