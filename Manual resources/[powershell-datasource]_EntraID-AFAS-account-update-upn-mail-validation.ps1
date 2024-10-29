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
