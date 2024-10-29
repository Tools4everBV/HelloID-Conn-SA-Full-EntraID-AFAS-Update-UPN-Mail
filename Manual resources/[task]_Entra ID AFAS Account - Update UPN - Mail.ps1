#######################################################################
# Template: HelloID SA Delegated form task
# Name:     EntraID-account-update-upn-mail
# Date:     12-09-2024
#######################################################################

# For basic information about delegated form tasks see:
# https://docs.helloid.com/en/service-automation/delegated-forms/delegated-form-powershell-scripts/add-a-powershell-script-to-a-delegated-form.html

# Service automation variables:
# https://docs.helloid.com/en/service-automation/service-automation-variables/service-automation-variable-reference.html

#region init
# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# global variables (Automation --> Variable libary):
# $globalVar = $globalVarName

# variables configured in form:
$entraidGUID = $form.gridUsers.Id
$displayname = $form.gridUsers.DisplayName
$employeeID = $form.gridUsers.employeeID


$currentUPN = $form.gridUsers.UserPrincipalName
$upnPrefixNew = $form.upnPrefix
$upnSuffixCurrent = $form.upnSuffixCurrent
$upnSuffixNew = $form.upnSuffixNew

$currentMail = $form.gridUsers.Mail
$mailPrefixNew = $form.mailPrefix
$mailSuffixCurrent = $form.mailSuffixCurrent
$mailSuffixNew = $form.mailSuffixNew

$currentMailNickName = $form.gridUsers.MailNickname
$newMailNickName = $form.mailNickName

$upnMailEqual = $form.upnMailEqual
#endregion init

#region global

if ([string]::IsNullOrEmpty($upnSuffixNew)) {
    $newUPN = $upnPrefixNew + $upnSuffixCurrent
}
else {
    $newUPN = $upnPrefixNew + $upnSuffixNew
}

if ($upnMailEqual -eq "True") {
    $newMail = $newUPN
    $newUPNNameSplit = $($newUPN).Split("@")
    $newMailNickName = $newUPNNameSplit[0]
}
else {
    if ([string]::IsNullOrEmpty($mailSuffixNew)) {
        $newMail = $mailPrefixNew + $mailSuffixCurrent
    }
    else {
        $newMail = $mailPrefixNew + $mailSuffixNew
    }
}
#endregion global

#region Entra ID functions
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
#endregion Entra ID functions

#region EntraID
try {
    $account = [PSCustomObject]@{   
        userPrincipalName = $newUPN
        mail              = $newMail
        mailNickname      = $newMailNickName 
    }

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
 
    $baseUpdateUri = "https://graph.microsoft.com/"
    $updateUri = $baseUpdateUri + "v1.0/users/$($entraidGUID)"
    $body = $account | ConvertTo-Json -Depth 10

    $response = Invoke-RestMethod -Uri $updateUri -Method PATCH -Headers $authorization -Body $body -Verbose:$false
        
    Write-Information "Finished updating Entra ID user [$displayname] attributes [userPrincipalName] from [$currentUPN] to [$newUPN], [mail] from [$currentMail] to [$newMail] and [mailNickname] from [$currentMailNickName] to [$newMailNickName]"
    $Log = @{
        Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
        System            = "Entra ID" # optional (free format text) 
        Message           = "Successfully updated Entra ID user [$displayname] attributes [userPrincipalName] from [$currentUPN] to [$newUPN], [mail] from [$currentMail] to [$newMail] and [mailNickname] from [$currentMailNickName] to [$newMailNickName]"
        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $displayname # optional (free format text) 
        TargetIdentifier  = $([string]$entraidGUID) # optional (free format text) 
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log    
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line [$($errorMessage.InvocationInfo.ScriptLineNumber)]: $($errorMessage.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))" 
    Write-Error "Failed to update Entra ID user [$displayname] attributes [userPrincipalName] from [$currentUPN] to [$newUPN], [mail] from [$currentMail] to [$newMail] and [mailNickname] from [$currentMailNickName] to [$newMailNickName]. Error: $($errorMessage.AuditErrorMessage)"
    $Log = @{
        Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
        System            = "Entra ID" # optional (free format text) 
        Message           = "Failed to update Entra ID user [$displayname] attributes [userPrincipalName] from [$currentUPN] to [$newUPN], [mail] from [$currentMail] to [$newMail] and [mailNickname] from [$currentMailNickName] to [$newMailNickName]"
        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $displayname # optional (free format text) 
        TargetIdentifier  = $([string]$entraidGUID) # optional (free format text) 
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log      
}
#endregion EntraID

#region AFAS
function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ''
        }
        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') {
            $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
        }
        Write-Output $httpErrorObj
    }
}
function Resolve-AFASErrorMessage {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        [object]$ErrorObject
    )
    process {
        try {
            $errorObjectConverted = $ErrorObject | ConvertFrom-Json -ErrorAction Stop

            if ($null -ne $errorObjectConverted.externalMessage) {
                $errorMessage = $errorObjectConverted.externalMessage
            }
            else {
                $errorMessage = $errorObjectConverted
            }
        }
        catch {
            $errorMessage = "$($ErrorObject.Exception.Message)"
        }

        Write-Output $errorMessage
    }
}

if (-not([string]::IsNullOrEmpty($employeeID))) {
    # Used to connect to AFAS API endpoints
    $BaseUri = $AFASBaseUrl
    $Token = $AFASToken
    $getConnector = "T4E_HelloID_Users_v2"
    $updateConnector = "KnEmployee"

    #Change mapping here
    $account = [PSCustomObject]@{
        'AfasEmployee' = @{
            'Element' = @{
                'Objects' = @(
                    @{
                        'KnPerson' = @{
                            'Element' = @{
                                'Fields' = @{
                                    # E-Mail werk  
                                    'EmAd' = $newMail                   
                                }
                            }
                        }
                    }
                )
            }
        }
    }

    $filterfieldid = "Medewerker"
    $filtervalue = $employeeID # Has to match the AFAS value of the specified filter field ($filterfieldid)

    # Get current AFAS employee and verify if a user must be either [created], [updated and correlated] or just [correlated]
    try {
        Write-Verbose "Querying AFAS employee with $($filterfieldid) $($filtervalue)"

        # Create authorization headers
        $encodedToken = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($Token))
        $authValue = "AfasToken $encodedToken"
        $Headers = @{ Authorization = $authValue }

        $splatWebRequest = @{
            Uri             = $BaseUri + "/connectors/" + $getConnector + "?filterfieldids=$filterfieldid&filtervalues=$filtervalue&operatortypes=1"
            Headers         = $headers
            Method          = 'GET'
            ContentType     = "application/json;charset=utf-8"
            UseBasicParsing = $true
        }        
        $currentAccount = (Invoke-RestMethod @splatWebRequest -Verbose:$false).rows

        if ($null -eq $currentAccount.Medewerker) {
            throw "No AFAS employee found with $($filterfieldid) $($filtervalue)"
        }
        Write-Information "Found AFAS employee [$($currentAccount.Medewerker)]"
        # Check if current EmAd has a different value from mapped value. AFAS will throw an error when trying to update this with the same value
        if ([string]$currentAccount.Email_werk -ne $account.'AfasEmployee'.'Element'.Objects[0].'KnPerson'.'Element'.'Fields'.'EmAd' -and $null -ne $account.'AfasEmployee'.'Element'.Objects[0].'KnPerson'.'Element'.'Fields'.'EmAd') {
            $propertiesChanged += @('EmAd')
        }
        if ($propertiesChanged) {
            Write-Verbose "Account property(s) required to update: [$($propertiesChanged -join ",")]"
            $updateAction = 'Update'
        }
        else {
            $updateAction = 'NoChanges'
        }

        # Update AFAS Employee
        Write-Verbose "Start updating AFAS employee [$($currentAccount.Medewerker)]"
        switch ($updateAction) {
            'Update' {
                # Create custom account object for update
                $updateAccount = [PSCustomObject]@{
                    'AfasEmployee' = @{
                        'Element' = @{
                            '@EmId'   = $currentAccount.Medewerker
                            'Objects' = @(@{
                                    'KnPerson' = @{
                                        'Element' = @{
                                            'Fields' = @{
                                                # Zoek op BcCo (Persoons-ID)
                                                'MatchPer' = 0
                                                # Nummer
                                                'BcCo'     = $currentAccount.Persoonsnummer
                                            }
                                        }
                                    }
                                })
                        }
                    }
                }
                if ('EmAd' -in $propertiesChanged) {
                    # E-mail werk
                    $updateAccount.'AfasEmployee'.'Element'.Objects[0].'KnPerson'.'Element'.'Fields'.'EmAd' = $account.'AfasEmployee'.'Element'.Objects[0].'KnPerson'.'Element'.'Fields'.'EmAd'
                    Write-Information "Updating BusinessEmailAddress '$($currentAccount.Email_werk)' with new value '$($updateAccount.'AfasEmployee'.'Element'.Objects[0].'KnPerson'.'Element'.'Fields'.'EmAd')'"
                }

                $body = ($updateAccount | ConvertTo-Json -Depth 10)
                $splatWebRequest = @{
                    Uri             = $BaseUri + "/connectors/" + $updateConnector
                    Headers         = $headers
                    Method          = 'PUT'
                    Body            = ([System.Text.Encoding]::UTF8.GetBytes($body))
                    ContentType     = "application/json;charset=utf-8"
                    UseBasicParsing = $true
                }

                $updatedAccount = Invoke-RestMethod @splatWebRequest -Verbose:$false
                Write-Information "Successfully updated attribute [EmAd] of AFAS employee [$employeeID] from [$($currentAccount.Email_werk)] to [$newMail]"
                $Log = @{
                    Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
                    System            = "AFAS Employee" # optional (free format text) 
                    Message           = "Successfully updated attribute [EmAd] of AFAS employee [$employeeID] from [$($currentAccount.Email_werk)] to [$newMail]" # required (free format text) 
                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = $displayName # optional (free format text) 
                    TargetIdentifier  = $([string]$employeeID) # optional (free format text) 
                }
                #send result back  
                Write-Information -Tags "Audit" -MessageData $log  
                break
            }
            'NoChanges' {
                Write-Information "Successfully checked attribute [EmAd] of AFAS employee [$employeeID] from [$($currentAccount.Email_werk)] to [$newMail], no changes needed"
                $Log = @{
                    Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
                    System            = "AFAS Employee" # optional (free format text) 
                    Message           = "Successfully checked attribute [EmAd] of AFAS employee [$employeeID] from [$($currentAccount.Email_werk)] to [$newMail], no changes needed" # required (free format text) 
                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = $displayName # optional (free format text) 
                    TargetIdentifier  = $([string]$employeeID) # optional (free format text) 
                }
                #send result back  
                Write-Information -Tags "Audit" -MessageData $log  
                break
            }
        }
    }
    catch {
        $ex = $PSItem
        if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
            $errorObject = Resolve-HTTPError -Error $ex

            $verboseErrorMessage = $errorObject.ErrorMessage

            $auditErrorMessage = Resolve-AFASErrorMessage -ErrorObject $errorObject.ErrorMessage
        }

        # If error message empty, fall back on $ex.Exception.Message
        if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
            $verboseErrorMessage = $ex.Exception.Message
        }
        if ([String]::IsNullOrEmpty($auditErrorMessage)) {
            $auditErrorMessage = $ex.Exception.Message
        }

        $ex = $PSItem
        $verboseErrorMessage = $ex
        if ($auditErrorMessage -Like "No AFAS employee found with $($filterfieldid) $($filtervalue)") {
            Write-Information "Skipped update attribute [EmAd] of AFAS employee [$employeeID] to [$newMail]: No AFAS employee found with $($filterfieldid) $($filtervalue)"
            $Log = @{
                Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
                System            = "AFAS Employee" # optional (free format text) 
                Message           = "Skipped update attribute [EmAd] of AFAS employee [$employeeID] to [$newMail]: No AFAS employee found with $($filterfieldid) $($filtervalue)" # required (free format text) 
                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = $displayName # optional (free format text) 
                TargetIdentifier  = $([string]$employeeID) # optional (free format text)
            }
            #send result back  
            Write-Information -Tags "Audit" -MessageData $log 
        }
        else {
            Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"
            Write-Error "Error updating AFAS employee $($currentAccount.Medewerker). Error Message: $auditErrorMessage"
            Write-Information "Error updating AFAS employee $($currentAccount.Medewerker). Error Message: $auditErrorMessage"
            $Log = @{
                Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
                System            = "AFAS Employee" # optional (free format text) 
                Message           = "Error updating AFAS employee $($currentAccount.Medewerker). Error Message: $auditErrorMessage" # required (free format text) 
                IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = $displayName # optional (free format text) 
                TargetIdentifier  = $([string]$employeeID) # optional (free format text) 
            }
            #send result back  
            Write-Information -Tags "Audit" -MessageData $log 
        }
    }
}
else {
    Write-Information "Skipped update attribute [EmAd] of AFAS employee [$displayName] to [$newMail]: employeeID is empty"
    $Log = @{
        Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
        System            = "AFAS Employee" # optional (free format text) 
        Message           = "Skipped update attribute [EmAd] of AFAS employee [$displayName] to [$newMail]: employeeID is empty" # required (free format text) 
        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $displayName # optional (free format text) 
        TargetIdentifier  = $([string]$employeeID) # optional (free format text)
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log 
}
#endregion AFAS
