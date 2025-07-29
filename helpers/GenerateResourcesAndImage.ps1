$ErrorActionPreference = 'Stop'

enum ImageType {
    Windows2019   = 1
    Windows2022   = 2
    Windows2025   = 3
    Ubuntu2204    = 4
    Ubuntu2404    = 5
}

Function Get-PackerTemplate {
    param (
        [Parameter(Mandatory = $True)]
        [string] $RepositoryRoot,
        [Parameter(Mandatory = $True)]
        [ImageType] $ImageType,
        [Parameter(Mandatory = $False)]
        [string] $BuildNameSuffix
    )

    switch ($ImageType) {
        # Note: Double Join-Path is required to support PowerShell 5.1
        ([ImageType]::Windows2019) {
            $relativeTemplatePath = Join-Path (Join-Path "windows" "templates") "build.windows-2019.pkr.hcl"
            $imageOS = "win19"
        }
        ([ImageType]::Windows2022) {
            $relativeTemplatePath = Join-Path (Join-Path "windows" "templates") "build.windows-2022.pkr.hcl"
            $imageOS = "win22"
        }
        ([ImageType]::Windows2025) {
            $relativeTemplatePath = Join-Path (Join-Path "windows" "templates") "build.windows-2025.pkr.hcl"
            $imageOS = "win25"
        }
        ([ImageType]::Ubuntu2204) {
            $relativeTemplatePath = Join-Path (Join-Path "ubuntu" "templates") "build.ubuntu-22_04.pkr.hcl"
            $imageOS = "ubuntu22"
        }
        ([ImageType]::Ubuntu2404) {
            $relativeTemplatePath = Join-Path (Join-Path "ubuntu" "templates") "build.ubuntu-24_04.pkr.hcl"
            $imageOS = "ubuntu24"
        }
        default { throw "Unknown type of image" }
    }

    $imageTemplatePath = [IO.Path]::Combine($RepositoryRoot, "images", $relativeTemplatePath)
    # Specific template selection using Packer's "-only" functionality
    $buildName = [IO.Path]::GetFileName($imageTemplatePath).Split(".")[1]

    if (-not (Test-Path $imageTemplatePath)) {
        throw "Template for image '$ImageType' doesn't exist on path '$imageTemplatePath'."
    }

    return [PSCustomObject] @{
        "BuildName" = $buildName + $BuildNameSuffix
        "ImageOS"   = $imageOS
        "Path"      = [IO.Path]::GetDirectoryName($imageTemplatePath)
    }
}

Function Show-LatestCommit {
    [CmdletBinding()]
    param()

    process {
        $latestCommit = (git --no-pager log --pretty=format:"Date: %cd; Commit: %H - %s; Author: %an <%ae>" -1)
        Write-Host "Latest commit: $latestCommit."
    }
}

function Start-Sleep($seconds) {
    $doneDT = (Get-Date).AddSeconds($seconds)
    while ($doneDT -gt (Get-Date)) {
        $secondsLeft = $doneDT.Subtract((Get-Date)).TotalSeconds
        $percent = ($seconds - $secondsLeft) / $seconds * 100
        Write-Progress -Activity "Sleeping" -Status "Sleeping..." -SecondsRemaining $secondsLeft -PercentComplete $percent
        [System.Threading.Thread]::Sleep(500)
    }
    Write-Progress -Activity "Sleeping" -Status "Sleeping..." -SecondsRemaining 0 -Completed
}

Function GenerateResourcesAndImage {
    <#
        .SYNOPSIS
            A helper function to help generate an image.
        .DESCRIPTION
            This function will generate the Azure resources and image for the specified image type.
        .PARAMETER DockerImageSource
            Build as docker image.
        .PARAMETER SubscriptionId
            The Azure subscription id where the Azure resources will be created.
        .PARAMETER ResourceGroupName
            The name of the resource group to store the resulting artifact. Resource group must already exist.
        .PARAMETER ImageType
            The type of image to generate. Valid values are: Windows2019, Windows2022, Windows2025, Ubuntu2204, Ubuntu2404.
        .PARAMETER ManagedImageName
            The name of the managed image to create. The default is "Runner-Image-{{ImageType}}".
        .PARAMETER AzureLocation
            The Azure location where the Azure resources will be created. For example: "East US"
        .PARAMETER ImageGenerationRepositoryRoot
            The root directory of the image generation repository. This is used to locate the packer template.
        .PARAMETER SecondsToWaitForServicePrincipalSetup
            The number of seconds to wait for the service principal to be setup. The default is 120 seconds.
        .PARAMETER AzureClientId
            The Azure client id to use to authenticate with Azure. If not specified, the current user's credentials will be used.
        .PARAMETER AzureClientSecret
            The Azure client secret to use to authenticate with Azure. If not specified, the current user's credentials will be used.
        .PARAMETER AzureTenantId
            The Azure tenant id to use to authenticate with Azure. If not specified, the current user's credentials will be used.
        .PARAMETER RestrictToAgentIpAddress
            If set, access to the VM used by packer to generate the image is restricted to the public IP address this script is run from. 
            This parameter cannot be used in combination with the virtual_network_name packer parameter.
        .PARAMETER OnError
            Specify how packer handles an error during image creation.
            Options:
                abort - abort immediately
                ask - ask user for input
                cleanup - attempt to cleanup and then abort
                run-cleanup-provisioner - run the cleanup provisioner and then abort
            The default is 'ask'.
        .PARAMETER Tags
            Tags to be applied to the Azure resources created.
        .PARAMETER PluginVersion
            Specify the version of the packer Azure plugin to use. The default is "2.2.1".
        .PARAMETER DockerPluginVersion
            Specify the version of the packer Docker plugin to use. The default is "1.1.1".
        .EXAMPLE
            GenerateResourcesAndImage -SubscriptionId {YourSubscriptionId} -ResourceGroupName "shsamytest1" -ImageGenerationRepositoryRoot "C:\runner-images" -ImageType Ubuntu2204 -AzureLocation "East US"
            GenerateResourcesAndImage -DockerImageSource -ImageType Ubuntu2204
    #>
    param (
        [Parameter(Mandatory = $True, ParameterSetName = 'Docker')]
        [switch] $DockerImageSource,
        [Parameter(Mandatory = $True, ParameterSetName = 'Azure')]
        [string] $SubscriptionId,
        [Parameter(Mandatory = $True, ParameterSetName = 'Azure')]
        [string] $ResourceGroupName,
        [Parameter(Mandatory = $True)]
        [ImageType] $ImageType,
        [Parameter(Mandatory = $False)]
        [string] $ManagedImageName = "Runner-Image-$($ImageType)",
        [Parameter(Mandatory = $True, ParameterSetName = 'Azure')]
        [string] $AzureLocation,
        [Parameter(Mandatory = $False)]
        [string] $ImageGenerationRepositoryRoot = $pwd,
        [Parameter(Mandatory = $False, ParameterSetName = 'Azure')]
        [int] $SecondsToWaitForServicePrincipalSetup = 120,
        [Parameter(Mandatory = $False, ParameterSetName = 'Azure')]
        [string] $AzureClientId,
        [Parameter(Mandatory = $False, ParameterSetName = 'Azure')]
        [string] $AzureClientSecret,
        [Parameter(Mandatory = $False, ParameterSetName = 'Azure')]
        [string] $AzureTenantId,
        [Parameter(Mandatory = $False)]
        [string] $PluginVersion = "2.2.1",
        [Parameter(Mandatory = $False)]
        [string] $DockerPluginVersion = "1.1.1",
        [Parameter(Mandatory = $False)]
        [switch] $RestrictToAgentIpAddress,
        [Parameter(Mandatory = $False)]
        [ValidateSet("abort", "ask", "cleanup", "run-cleanup-provisioner")]
        [string] $OnError = "ask",
        [Parameter(Mandatory = $False)]
        [hashtable] $Tags = @{}
    )

    Show-LatestCommit -ErrorAction SilentlyContinue
    Write-Debug "ParameterSetName: $($PSCmdlet.ParameterSetName)."

    # Validate packer is installed
    $PackerBinary = Get-Command "packer"
    if (-not ($PackerBinary)) {
        throw "'packer' binary is not found on PATH."
    }

    # Get template path
    $BuildNameSuffix = ""
    switch ($PSCmdlet.ParameterSetName) {
        ('Azure') {
            $BuildNameSuffix = ".azure-arm.azure-image"
        }
        ('Docker') {
            $BuildNameSuffix = ".docker.docker-image"
        }
    }
    $PackerTemplate = Get-PackerTemplate -RepositoryRoot $ImageGenerationRepositoryRoot -ImageType $ImageType -BuildNameSuffix $BuildNameSuffix
    Write-Debug "Template path: $($PackerTemplate.Path)."

    # Prepare list of allowed inbound IP addresses
    if ($RestrictToAgentIpAddress) {
        $AgentIp = (Invoke-RestMethod https://ipinfo.io/json).ip
        if (-not $AgentIp) {
            throw "Unable to determine agent IP address."
        }

        Write-Host "Access to packer generated VM will be restricted to agent IP Address: $AgentIp."
        if ($PSVersionTable.PSVersion.Major -eq 5) {
            Write-Verbose "PowerShell 5 detected. Replacing double quotes with escaped double quotes in allowed inbound IP addresses."
            $AllowedInboundIpAddresses = '[\"{0}\"]' -f $AgentIp
        }
        elseif ($PSVersionTable.PSVersion.Major -eq 7 -and $PSVersionTable.PSVersion.Minor -le 2) {
            Write-Verbose "PowerShell 7.0-7.2 detected. Replacing double quotes with escaped double quotes in allowed inbound IP addresses."
            $AllowedInboundIpAddresses = '[\"{0}\"]' -f $AgentIp
        }
        else {
            $AllowedInboundIpAddresses = '["{0}"]' -f $AgentIp
        }
    }
    else {
        $AllowedInboundIpAddresses = "[]"
    }
    Write-Debug "Allowed inbound IP addresses: $AllowedInboundIpAddresses."

    # Prepare tags
    $TagsList = $Tags.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
    Write-Debug "Tags list: $TagsList."
    $TagsJson = $Tags | ConvertTo-Json -Compress
    if ($PSVersionTable.PSVersion.Major -eq 5) {
        Write-Verbose "PowerShell 5 detected. Replacing double quotes with escaped double quotes in tags JSON."
        $TagsJson = $TagsJson -replace '"', '\"'
    }
    elseif ($PSVersionTable.PSVersion.Major -eq 7 -and $PSVersionTable.PSVersion.Minor -le 2) {
        Write-Verbose "PowerShell 7.0-7.2 detected. Replacing double quotes with escaped double quotes in tags JSON."
        $TagsJson = $TagsJson -replace '"', '\"'
    }
    Write-Debug "Tags JSON: $TagsJson."

    $InstallPassword = $env:UserName + [System.GUID]::NewGuid().ToString().ToUpper()

    Write-Host "Downloading packer plugins..."
    & $PackerBinary plugins install github.com/hashicorp/azure $PluginVersion `
        && & $PackerBinary plugins install github.com/hashicorp/docker $DockerPluginVersion

    if ($LastExitCode -ne 0) {
        throw "Packer plugins download failed."
    }

    Write-Host "Validating packer template..."
    $AddValidateParams = @()
    switch ($PSCmdlet.ParameterSetName) {
        ('Azure') {
            $AddValidateParams = @(
                "-var=client_id=fake",
                "-var=client_secret=fake",
                "-var=subscription_id=$($SubscriptionId)",
                "-var=tenant_id=fake",
                "-var=location=$($AzureLocation)",
                "-var=managed_image_resource_group_name=$($ResourceGroupName)",
                "-var=azure_tags=$($TagsJson)"
            )
        }
        default { }
    }
    & $PackerBinary validate `
        "-only=$($PackerTemplate.BuildName)*" `
        "-var=image_os=$($PackerTemplate.ImageOS)" `
        "-var=managed_image_name=$($ManagedImageName)" `
        "-var=install_password=$($InstallPassword)" `
        "-var=allowed_inbound_ip_addresses=$($AllowedInboundIpAddresses)" `
        $AddValidateParams `
        $PackerTemplate.Path

    if ($LastExitCode -ne 0) {
        throw "Packer template validation failed."
    }

    try {
        if ($PSCmdlet.ParameterSetName -eq 'Azure') {
            # Login to Azure subscription
            if ([string]::IsNullOrEmpty($AzureClientId)) {
                Write-Verbose "No AzureClientId was provided, will use interactive login."
                az login --output none
            }
            else {
                Write-Verbose "AzureClientId was provided, will use service principal login."
                az login --service-principal --username $AzureClientId --password=$AzureClientSecret --tenant $AzureTenantId --output none
            }
            az account set --subscription $SubscriptionId
            if ($LastExitCode -ne 0) {
                throw "Failed to login to Azure subscription '$SubscriptionId'."
            }

            # Check resource group
            $ResourceGroupExists = [System.Convert]::ToBoolean((az group exists --name $ResourceGroupName));
            if ($ResourceGroupExists) {
                Write-Verbose "Resource group '$ResourceGroupName' already exists."
            }
            else {
                throw "Resource group '$ResourceGroupName' does not exist."
            }

            # Create service principal
            if ([string]::IsNullOrEmpty($AzureClientId)) {
                Write-Host "Creating service principal for packer..."
                $ADCleanupRequired = $true

                $ServicePrincipalName = "packer-" + [System.GUID]::NewGuid().ToString().ToUpper()
                $ServicePrincipal = az ad sp create-for-rbac --name $ServicePrincipalName --role Contributor --scopes /subscriptions/$SubscriptionId --only-show-errors | ConvertFrom-Json
                if ($LastExitCode -ne 0) {
                    throw "Failed to create service principal '$ServicePrincipalName'."
                }

                $ServicePrincipalAppId = $ServicePrincipal.appId
                $ServicePrincipalPassword = $ServicePrincipal.password
                $TenantId = $ServicePrincipal.tenant

                Write-Verbose "Waiting for service principal to propagate..."
                Start-Sleep $SecondsToWaitForServicePrincipalSetup
                Write-Host "Service principal created with id '$ServicePrincipalAppId'. It will be deleted after the build."
            }
            else {
                $ServicePrincipalAppId = $AzureClientId
                $ServicePrincipalPassword = $AzureClientSecret
                $TenantId = $AzureTenantId
            }
            Write-Debug "Service principal app id: $ServicePrincipalAppId."
            Write-Debug "Tenant id: $TenantId."
        }

        $AddBuildParams = @()
        switch ($PSCmdlet.ParameterSetName) {
            ('Azure') {
                $AddBuildParams = @(
                    "-var=client_id=$($ServicePrincipalAppId)",
                    "-var=client_secret=$($ServicePrincipalPassword)",
                    "-var=subscription_id=$($SubscriptionId)",
                    "-var=tenant_id=$($TenantId)",
                    "-var=location=$($AzureLocation)",
                    "-var=managed_image_resource_group_name=$($ResourceGroupName)",
                    "-var=azure_tags=$($TagsJson)"
                )
            }
            default { }
        }

        & $PackerBinary build -on-error="$($OnError)" `
            -only "$($PackerTemplate.BuildName)*" `
            -var "image_os=$($PackerTemplate.ImageOS)" `
            -var "managed_image_name=$($ManagedImageName)" `
            -var "install_password=$($InstallPassword)" `
            -var "allowed_inbound_ip_addresses=$($AllowedInboundIpAddresses)" `
            $AddBuildParams `
            $PackerTemplate.Path

        if ($LastExitCode -ne 0) {
            throw "Failed to build image."
        }
    } catch {
        Write-Error $_
    } finally {
        Write-Verbose "`nCleaning up..."

        if ($PSCmdlet.ParameterSetName -eq 'Azure') {
            # Remove ADServicePrincipal and ADApplication
            if ($ADCleanupRequired) {
                Write-Host "Removing ADServicePrincipal..."
                if (az ad sp show --id $ServicePrincipalAppId --query id) {
                    az ad sp delete --id $ServicePrincipalAppId
                }

                Write-Host "Removing ADApplication..."
                if (az ad app show --id $ServicePrincipalAppId --query id) {
                    az ad app delete --id $ServicePrincipalAppId
                }
            }
        }

        Write-Verbose "Cleanup completed."
    }
}
