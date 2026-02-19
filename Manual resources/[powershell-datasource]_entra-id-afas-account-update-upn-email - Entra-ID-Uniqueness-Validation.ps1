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

