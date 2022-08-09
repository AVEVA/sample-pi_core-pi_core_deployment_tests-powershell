#requires -version 4.0
<##############################################################################

Functions for setting up OSIsoft test environment and running work flow.

###############################################################################>

### Constants ###
## OSIsoftTests ##
$Root = Split-Path -Path $PSScriptRoot -Parent
$BuildPlatform = 'Any CPU'
$BuildConfiguration = 'Release'
$WindFarmxml = Join-Path $Root 'xml\OSIsoftTests-Wind.xml'
$Source = Join-Path $Root 'source'
$BuildPath = Join-Path $Root 'build'
$BinPath = Join-Path $Root 'source\bin\release'
$Logs = Join-Path $Root 'logs'
$AppConfigFile = Join-Path $Source 'Run.config'
$RunConfigFile = Join-Path $BinPath 'Run.config'
$TestResults = Join-Path $Root 'testResults'
$Solution = Join-Path $Source 'OSIsoft.PISystemDeploymentTests.sln'
$Binaries = Join-Path $Source 'bin' | Join-Path -ChildPath $BuildConfiguration
$TestDll = Join-Path $Binaries 'OSIsoft.PISystemDeploymentTests.dll'
$PSEErrorHandlingMsg = "Please use PI System Explorer to run this step and troubleshoot any potential issues."
$TestsPIPointSource = "OSIsoftTests"
$SamplePIPoint = "OSIsoftTests.Region 0.Wind Farm 00.TUR00000.SineWave"
$CoveredByRecalcPIPointRegex = "Random|SineWave"
$DefaultPIDataStartTime = "*-1d"
$PIAnalysisServicePort = 5463
$WaitIntervalInSeconds = 10
$MaxRetry = 120
$RetryCountBeforeReporting = 18
$LastTraceTime = Get-Date
$FormatedLastTraceTime = "OSIsoftTests_{0:yyyy.MM.dd@HH-mm-ss}" -f $Script:LastTraceTime
$ExecutionLog = Join-Path $Logs "$FormatedLastTraceTime.log"
$MaxLogFileCount = 50
$TestResultFile = Join-Path $TestResults "$FormatedLastTraceTime.html"
$PreCheckTestResultFile = Join-Path $TestResults ($FormatedLastTraceTime + "_PreCheck.html")
$RequiredSettings = @("PIDataArchive", "AFServer", "AFDatabase", "PIAnalysisService")
$HiddenSettingsRegex = "user|password|encrypt"
# A hashtable mapping the appSettings to the test classes of optional products with a string key setting.
$TestClassesForOptionalProductWithKeySetting = @{ 
    PINotificationsService = "NotificationTests";
    PIWebAPI               = "PIWebAPITests";
    PIManualLogger         = "ManualLoggerTests"; 
    PIVisionServer         = "Vision3Tests"
}
# A hashtable mapping the appSettings to the test classes of optional products with a boolean key setting.
$TestClassesForOptionalProductWithBooleanFlag = @{ 
    PIDataLinkTests  = "DataLinkAFTests,DataLinkPIDATests"; 
    PISqlClientTests = "PISqlClientTests"
}
## Build Tools ##
$DefaultMSBuildVersion = 15
$NuGetExe = Join-Path $Root '.nuget\nuget.exe'
$MSBuildExe = ""
$TempDir = Join-Path $Root 'temp'
$DotNETFrameworkDir = "${Env:ProgramFiles(x86)}\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.8"
$DotNETDevPackFileName = 'ndp48-devpack-enu.exe'
$DotNETDevPack = Join-Path $TempDir $DotNETDevPackFileName
$VSBuildToolsFileName = 'VS_BuildTools.exe'
$VSBuildTools = Join-Path $TempDir $VSBuildToolsFileName
$NuGetExeUri = "https://dist.nuget.org/win-x86-commandline/latest/nuget.exe"
$DotNETDevPackUri = "https://download.visualstudio.microsoft.com/download/pr/7afca223-55d2-470a-8edc-6a1739ae3252/" +
"c8c829444416e811be84c5765ede6148/ndp48-devpack-enu.exe"
$VSBuildToolsUri = "https://download.visualstudio.microsoft.com/download/pr/e730a0bd-baf1-4f4c-9341-ca5a9caf0f9f/" + 
"fc975c3678921adacfce4d912efe88d5846b354f39db6314cb69947cdc1d6d2b/vs_buildtools.exe"
$xUnitConsole = Join-Path $Source 'packages\xunit.runner.console.2.4.1\tools\net471\xunit.console.exe'
$xUnitConsolePath = Join-Path $Source 'packages\xunit.runner.console.2.4.1\tools\net471\'
$VsWhereExe = "${Env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$BuildTools = "${Env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\BuildTools"


function Add-VerboseLog() {
    [cmdletbinding()]
    param
    (
        [string]
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        $Message,

        [switch]
        [Parameter(Mandatory = $false)]
        $Log = [switch]::Present
    )
    $processedMessage = "[$(Trace-Time)]`t$Message"
    Write-Verbose  $processedMessage

    #If logging is enabled, write to file
    if ($Log) { try { $processedMessage | Write-ExecutionLog } catch { $_ = $Error } }
}


function Add-InfoLog() {
    [cmdletbinding()]
    param
    (
        [string]
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        $Message,

        [switch]
        [Parameter(Mandatory = $false)]
        $Log = [switch]::Present
    )
    $processedMessage = "[$(Trace-Time)]`t$Message"
    Write-Host $processedMessage

    #If logging is enabled, write to file
    if ($Log) { try { $processedMessage | Write-ExecutionLog } catch { $_ = $Error } }
}


function Add-WarningLog() {
    [cmdletbinding()]
    param
    (
        [string]
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        $Message,

        [switch]
        [Parameter(Mandatory = $false)]
        $Log = [switch]::Present
    )
    $processedMessage = "[$(Trace-Time)]`t$Message"
    Write-Warning $processedMessage

    #If logging is enabled, write to file
    if ($Log) { try { $processedMessage | Write-ExecutionLog } catch { $_ = $Error } }
}


function Add-ErrorLog {
    [cmdletbinding()]
    param
    (
        [string]
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        $Message,

        [switch]
        [Parameter(Mandatory = $false)]
        $Log = [switch]::Present,

        [switch]
        [Parameter(Mandatory = $false)]
        $Fatal
    )
    $processedMessage = "[$(Trace-Time)]`t$Message"

    #If logging is enabled, write to file
    if ($Log) { try { $processedMessage | Write-ExecutionLog } catch { $_ = $Error } }

    if (-not $Fatal) {
        Write-Host $processedMessage -ForegroundColor Red
    }
    else {
        Write-Host ($processedMessage + [Environment]::NewLine) -ForegroundColor Red
        exit 1
    }
}


function Write-ExecutionLog {
    [cmdletbinding()]
    param
    (
        [string]
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        $Message,

        [int32]
        [Parameter(Mandatory = $false)]
        $MaxLogs = $MaxLogFileCount
    )
    Begin {
        # Prepare the log path and file
        $logFolder = Split-Path $ExecutionLog -Parent
        New-FolderIfNotExists($logFolder)

        # Create the logs folder if missing and remove old logs
        if (!(Test-Path -Path $ExecutionLog)) {
            New-Item -ItemType File -Path $ExecutionLog -Force > $null
        
            $logCount = (Get-ChildItem $logFolder | Measure-Object).Count
            $logsByDate = (Get-ChildItem $logFolder | Sort-Object -Property CreationDate)
            $logIndex = 0

            while ($logCount -ge $MaxLogs) {
            
                Remove-Item -Path $logsByDate[$logIndex].FullName
                $logCount -= 1
                $logIndex += 1
            }
        }
    }
    Process {
        # Write the message to the log file
        Write-Output $_ >> $ExecutionLog
    }
}


function Trace-Time() {
    [CmdletBinding()]
    param ()
    $currentTime = Get-Date
    $lastTime = $Script:LastTraceTime
    $Script:LastTraceTime = $currentTime
    "{0:HH:mm:ss} +{1:F0}" -f $currentTime, ($currentTime - $lastTime).TotalSeconds
}


function Format-ElapsedTime($ElapsedTime) {
    '{0:D2}:{1:D2}:{2:D2}' -f $ElapsedTime.Hours, $ElapsedTime.Minutes, $ElapsedTime.Seconds
}


function New-FolderIfNotExists {
    [CmdletBinding()]
    param (
        [string]$FolderPath
    )
    if (!(Test-Path $FolderPath)) {
        New-Item -ItemType Directory -Force -Path $FolderPath
    }
}


function Install-NuGet {
    [CmdletBinding()]
    param()
    if (-not (Test-Path $NuGetExe)) {
        $NuGetFolder = Split-Path -Path $NuGetExe -Parent
        New-FolderIfNotExists($NuGetFolder)

        Add-InfoLog -Message "Downloading nuget.exe."

        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

        Invoke-WebRequest $NuGetExeUri -OutFile $NuGetExe

        if (Test-Path $NuGetExe) {
            Add-InfoLog -Message "Downloaded nuget.exe successfully."
        }
        else {
            Add-ErrorLog -Message "Failed to download nuget.exe." -Fatal
        }
    }
}


function Install-DotNETDevPack {
    [CmdletBinding()]
    param()
    if (-not (Test-Path $DotNETFrameworkDir)) {
        if (-not (Test-Path $DotNETDevPack)) {
            New-FolderIfNotExists($TempDir)

            Add-InfoLog -Message "Downloading $DotNETDevPackFileName."
            Invoke-WebRequest $DotNETDevPackUri -OutFile $DotNETDevPack
            Add-InfoLog -Message "Downloaded $DotNETDevPackFileName."
        }

        # Install .NET Framework Developer Pack
        # Warn user about the reboot if .NET runtime will also be installed
        if ((Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Release -lt 528040) {
            $proceed = Get-UserBooleanInput -Message ("The script will install .NET Framework of 4.8 and require a reboot after the installation, " + 
                "you may select 'Y' to proceed or 'N' to exit if you are not ready.")
            if (-not $proceed) {
                exit
            }
        }

        $p = Start-Process $DotNETDevPack -ArgumentList "/install /quiet" -PassThru -Wait
        if ($p.ExitCode -ne 0 -or -not (Test-Path $DotNETFrameworkDir)) {
            Add-ErrorLog -Message ("Failed to install .NET Developer Pack. " + 
                "Please run ""$DotNETDevPack"" interactively and troubleshoot any issues.") -Fatal
        }
        
        Add-InfoLog -Message "Installed .NET Developer Pack successfully."
    }
}

function Restore-SolutionPackages {
    [CmdletBinding()]
    param(
        [Alias('path')]
        [string]$SolutionPath,
        [ValidateSet(15)]
        [int]$MSBuildVersion
    )

    $opts = , 'restore'
    if (-not $SolutionPath) {
        $opts += $Source
    }
    else {
        $opts += $SolutionPath
    }

    if ($MSBuildVersion) {
        $opts += '-MSBuildVersion', $MSBuildVersion
    }

    if (-not $VerbosePreference) {
        $opts += '-verbosity', 'quiet'
    }

    Add-InfoLog -Message "Restoring Packages"
    Add-InfoLog -Message $Source

    & $NuGetExe $opts
    if (-not $?) {
        Add-ErrorLog -Message "Restore failed @""$Root"". Code: ${LASTEXITCODE}."
    }
}

function Build-ExcludedTestClassesString {
    [CmdletBinding()]
    param ()
    if (-not $Script:ConfigureHashTable) {
        Read-PISystemConfig -Force > $null
    }

    $noClassString = ""

    foreach ($key in $TestClassesForOptionalProductWithKeySetting.Keys) {
        if (-not $Script:ConfigureHashTable.ContainsKey($key) -or 
            [string]::IsNullOrEmpty($Script:ConfigureHashTable[$key])) {
            foreach ($testClass in $TestClassesForOptionalProductWithKeySetting[$key].split(',')) {
                $noClassString += '-noclass "{0}" ' -f ("OSIsoft.PISystemDeploymentTests.$testClass")        
            }
        }
    }
    
    foreach ($key in $TestClassesForOptionalProductWithBooleanFlag.Keys) {
        if ($Script:ConfigureHashTable.ContainsKey($key)) {
            $runTests = $null
            if (-not [bool]::TryParse($Script:ConfigureHashTable[$key], [ref]$runTests)) {
                Add-ErrorLog -Message "The setting value of ""$key"" in App.config is not boolean."
            }

            if (-not $runTests) {
                foreach ($testClass in $TestClassesForOptionalProductWithBooleanFlag[$key].split(',')) {
                    $noClassString += '-noclass "{0}" ' -f ("OSIsoft.PISystemDeploymentTests.$testClass")        
                }
            }
        }
    }

    $noClassString.Trim()
}

function Setup-Tests {
    [CmdletBinding()]
    param ()
    # In order to build xUnit test solution, we need .NET Framework Developer Pack, NuGet.exe, and MSBuild
    Add-InfoLog -Message "Install .NET Framework Developer Pack if missing."
    Install-DotNETDevPack

    Add-InfoLog -Message "Install NuGet.exe if missing."
    Install-NuGet

    Add-InfoLog -Message "Install MSBuild if missing."
    Install-BuildTools

    Add-InfoLog -Message "Restore the NuGet packages of the test solution."
    Restore-SolutionPackages

    Copy-Run-Config
}

function Copy-Run-config
{
    Add-InfoLog -Message "Copying Run.config to users temp folder."

    $ConfigDestination = Join-Path $env:TEMP '\Run.config'

    Add-InfoLog -Message $RunConfigFile
    Add-InfoLog -Message $ConfigDestination

    Copy-Item $RunConfigFile -Destination $ConfigDestination
}

function Start-PrelimTesting {
    [CmdletBinding()]
    param ()
    Add-InfoLog -Message "Run Preliminary Checks."
    try {
        & $xUnitConsole $TestDll -class "OSIsoft.PISystemDeploymentTests.PreliminaryChecks" -html ""$PreCheckTestResultFile"" -verbose | 
        Tee-Object -Variable "preliminaryCheckResults"
        $preliminaryCheckResults | Write-ExecutionLog
        $errorTestCount = [int]($preliminaryCheckResults[-1] -replace ".*Errors: (\d+),.*", '$1')
        $failedTestCount = [int]($preliminaryCheckResults[-1] -replace ".*Failed: (\d+),.*", '$1')
    }
    catch {
        Add-ErrorLog -Message "Failed to run the PreliminaryChecks"
        Add-ErrorLog -Message ($_ | Out-String) -Fatal
	}

    if (($errorTestCount + $failedTestCount) -gt 0) {
        Add-ErrorLog -Message "Preliminary Checks failed, please troubleshoot the errors and try again." -Fatal
    }
}

function Start-Testing {
    [CmdletBinding()]
    param
    (
        [String]
        [Parameter(Mandatory = $false)]
        $TestName = '',
        $TestClassName = ''
    )
    if (-not (Test-Path $TestDll)) {
        Add-ErrorLog -Message "@""$TestDll"" is not available, please build the solution first." -Fatal
    }

    if ($TestName -ne '' -and $TestClassName -ne '') {
        Add-InfoLog -Message "Run product test '$TestName'."
        $fullCommand = "& $xUnitConsole $TestDll -method OSIsoft.PISystemDeploymentTests.$TestClassName.$TestName -verbose -parallel none"
    }
    elseif ($TestClassName -ne '') {
        Add-InfoLog -Message "Run product test class '$TestClassName'."
        $fullCommand = "& $xUnitConsole $TestDll -class OSIsoft.PISystemDeploymentTests.$TestClassName -verbose -parallel none"
    }
    else {
        $excludedTestClassesString = '-noclass "OSIsoft.PISystemDeploymentTests.PreliminaryChecks" ' + 
        (Build-ExcludedTestClassesString)
        Add-InfoLog -Message "Run product tests."
        $fullCommand = '& $xUnitConsole $TestDll --% ' + $excludedTestClassesString + 
        " -html ""$TestResultFile"" -verbose -parallel none"
    }

    Add-InfoLog -Message $fullCommand
    try {
        Invoke-Expression $fullCommand | Tee-Object -Variable "productTestResults"
        $productTestResults | Write-ExecutionLog
        $errorTestCount = [int]($productTestResults[-1] -replace ".*Errors: (\d+),.*", '$1')
        $failedTestCount = [int]($productTestResults[-1] -replace ".*Failed: (\d+),.*", '$1')
    }
    catch {
        Add-ErrorLog -Message "Failed to execute the full xUnit test run"
        Add-ErrorLog -Message ($_ | Out-String) -Fatal
	}

    if (($errorTestCount + $failedTestCount) -gt 0 -and $TestName -eq '' -and $TestClassName -eq '') {
        Add-ErrorLog -Message "xUnit test run finished with some failures, please troubleshoot the errors in $TestResultFile."
    }
    elseif (($errorTestCount + $failedTestCount) -eq 0 -and $TestName -eq '' -and $TestClassName -eq '') {
        Add-InfoLog -Message "xUnit test run finished, test results were saved in $TestResultFile."
    }
}


function Read-PISystemConfig {
    [CmdletBinding()]
    param (
        # Switch to skip confirmation
        [switch]$Force
    ) 
    Encrypt-PIWebAPICredentials
    $ConfigureSettings = Read-AppSettings
    Add-InfoLog ($ConfigureSettings | Out-String).TrimEnd()

    if (-not $Force) {
        Write-Host
        Add-InfoLog -Message ("Please double check the above PI System configuration loaded from $AppConfigFile," + 
            " update the file using a text editor if needed, press enter to continue...")
        Read-Host > $null
        Write-Host

        # Read the config again 
        Add-InfoLog -Message "Execution will continue with following settings."
        $ConfigureSettings = Read-AppSettings
        Add-InfoLog ($ConfigureSettings | Out-String).TrimEnd()
    }

    # Convert the setting array into properties, save the copy in a hashtable
    $ConfigureObject = New-Object PSObject
    $Script:ConfigureHashTable = @{ }
    $ConfigureSettings | ForEach-Object { 
        $AddMemberParams = @{
            InputObject       = $ConfigureObject
            NotePropertyName  = $_.Setting
            NotePropertyValue = $_.Value 
        }
        Add-Member @AddMemberParams

        $Script:ConfigureHashTable.Add($_.Setting, $_.Value)
    }
    
    foreach ($setting in $RequiredSettings) {
        if (-not $Script:ConfigureHashTable.ContainsKey($setting) -or 
            [string]::IsNullOrEmpty($Script:ConfigureHashTable[$setting])) {
            Add-ErrorLog -Message ("The required setting, $setting, is missing or has an empty value. " + 
                "Please fix it in App.config") -Fatal
        }
    }

    $ConfigureObject
}

function Encrypt-PIWebAPICredentials {
    [CmdletBinding()]
    param ()
    $Script:ConfigureData = @{ }
    ([xml](Get-Content $AppConfigFile)).Configuration.AppSettings.Add | 
    ForEach-Object { 
        $Script:ConfigureData.Add($_.key, $_.value)
    }

    $CredentialEncryptValue = $Script:ConfigureData["PIWebAPIEncryptionID"]
    if ((![string]::IsNullOrWhitespace($Script:ConfigureData["PIWebAPIUser"]) -and ![string]::IsNullOrWhitespace($Script:ConfigureData["PIWebAPIPassword"])) -and 
        [string]::IsNullOrWhitespace($CredentialEncryptValue)) {
            Add-Type -AssemblyName "System.Security"

            Write-Host
            Write-Host "Encrypting and writing to App.config..."

            $Entropy = New-Object byte[] 16
            $RNG = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
            $RNG.GetBytes($Entropy)

            $AppConfigXML = New-Object XML
            $AppConfigXML.Load($AppConfigFile)
            $ProtectionScope = [System.Security.Cryptography.DataProtectionScope]
            foreach ($Setting in $AppConfigXML.Configuration.AppSettings.Add) {
                if ($Setting.key -eq "PIWebAPIUser") {
                    $ToEncryptUser = [System.Text.Encoding]::ASCII.GetBytes($Setting.value)
                    $EncryptedUser = Encrypt-CredentialData $ToEncryptUser $Entropy $ProtectionScope::CurrentUser
                    $Setting.value = [System.BitConverter]::ToString($EncryptedUser)
				}

                if ($Setting.key -eq "PIWebAPIPassword") {
                    $ToEncryptPass = [System.Text.Encoding]::ASCII.GetBytes($Setting.value)
                    $EncryptedPass = Encrypt-CredentialData $ToEncryptPass $Entropy $ProtectionScope::CurrentUser
                    $Setting.value = [System.BitConverter]::ToString($EncryptedPass)
				}

                if ($Setting.key -eq "PIWebAPIEncryptionID") {
                    $Setting.value = [System.BitConverter]::ToString($Entropy)
				}
            }

            $AppConfigXML.Save($AppConfigFile)
    }
}

function Encrypt-CredentialData {
    [CmdletBinding()]
    param (
        [byte[]]$Buffer,
        [byte[]]$Entropy,
        [System.Security.Cryptography.DataProtectionScope]$Scope
    )

    # Encrypt the data and store the result in a new byte array. The original data remains unchanged.
    $EncryptedData = [System.Security.Cryptography.ProtectedData]::Protect($Buffer, $Entropy, $Scope);
    return $EncryptedData
}

function Read-AppSettings {
    [CmdletBinding()]
    param ()

    Add-InfoLog -Message $RunConfigFile

    ([xml](Get-Content $RunConfigFile)).Configuration.AppSettings.Add | 
    Select-Object -property @{
        Name = 'Setting'; Expression = { $_.key } 
    }, 
    @{
        Name = 'Value'; Expression = { if ($_.key -match $HiddenSettingsRegex -and $_.value ) { "********" } else { $_.value } } 
    }
}


function Get-UserBooleanInput {
    [CmdletBinding()]
    param (
        # Message presented to the user
        [string]$Message = ""
    )
    
    $flag = 'n'
    do {
        Add-InfoLog -Message ($Message + " (Y/N)")
        $flag = (Read-Host | Tee-Object -FilePath $ExecutionLog -Append).ToLower()
    } until ('y', 'n' -contains $flag)

    if ($flag -eq 'y') {
        $true
    }
    else {
        $false
    }
}


# load OSIsoft.AFSDK.dll for the following PI/AF related functions
Add-Type -AssemblyName 'OSIsoft.AFSDK, Version=4.0.0.0, Culture=neutral, PublicKeyToken=6238be57836698e6' > $null


function Set-TargetDatabase {
    [CmdletBinding()]
    param(
        # AF Server object
        [Parameter(Mandatory = $true)]
        [OSIsoft.AF.PISystem]$PISystem,

        # Name of AF Database
        [Parameter(Mandatory = $true)]
        [string]$Database,

        # PI Data Archive ClientChannel
        [Parameter(Mandatory = $true)]
        [OSIsoft.PI.Net.ClientChannel]$PIDA,

        # Switch to force rebuilding database, it will override the Reset switch if both are specified
        [switch]$Force
    )   
    $db = $PISystem.Databases[$Database]
    $buildDatabase = $true

    if ($db) {
        if (-not $Force) {
            $buildDatabase = Get-UserBooleanInput("Found existing AF database, $($db.GetPath())." + 
                [Environment]::NewLine +
                "Do you want to remove this database and build one from scratch?")
        }

        if ($buildDatabase) {
            try {
                $RemoveTargetDatabaseParams = @{
                    PISystem = $PISystem
                    Database = $Database
                    PIDA     = $PIDA
                    Force    = $true
                }
                Remove-TargetDatabase @RemoveTargetDatabaseParams
            }
            catch {
                Add-ErrorLog -Message ($_ | Out-String) -Fatal
            } 
        }
        else {
            Add-InfoLog -Message "Execution will continue with the current AF database."
        }
    }

    if ($buildDatabase) {
        try {
            Add-InfoLog -Message "Start building the target PI AF database."
            
            Add-InfoLog -Message "Start xml importing."
            $PISystem.ImportXml($null, 1041, $WindFarmxml) > $null

			$db = $PISystem.Databases[$Database]
            $elementSearch = New-Object OSIsoft.AF.Search.AFElementSearch $db, "AllElements", ""
            # Pause for the xml importing to finish, otherwise CreateConfig may throw errors.
            $attempt = 0
            $elementCount = $elementSearch.GetTotalCount()
            do {
                Start-Sleep -Seconds $WaitIntervalInSeconds

                if (($elementSearch.GetTotalCount() -eq $elementCount) -and -not $db.IsDirty) {
                    break
                }
                else {
                    $elementCount = $elementSearch.GetTotalCount()
                }

                if ((++$attempt % $RetryCountBeforeReporting) -eq 0) {
                    Add-InfoLog -Message "Waiting on xml importing to finish..."
                }
            }while ($attempt -lt $MaxRetry)

            if ($attempt -eq $MaxRetry) {
                Add-WarningLog -Message ("The step of importing a xml file to $($db.GetPath()) " + 
                    "did not finish after $($WaitIntervalInSeconds * $MaxRetry) seconds.")
            }
            else {
                Add-InfoLog -Message "Finished xml importing."
            }
            
            $PIDAAttribute = $db.Elements["PI Data Archive"].Attributes["Name"]
            Set-AFAttribute -AFAttribute $PIDAAttribute -Value $PIDA.CurrentRole.Name -ErrorAction Stop
        }
        catch {
            Add-ErrorLog -Message ($_ | Out-String) -Fatal                
        }

        $createConfigSecondTry = $false
        [System.EventHandler[OSIsoft.AF.AFProgressEventArgs]]$hndl = {
            if (($_.Status -eq [OSIsoft.AF.AFProgressStatus]::HasError) -or
                ($_.Status -eq [OSIsoft.AF.AFProgressStatus]::CompleteWithErrors)) {
                $_.Cancel = $true

                if ($createConfigSecondTry) {
                    Add-ErrorLog -Message ("Encountered errors when trying to create or update PI Point data reference in " + 
                        "$($db.GetPath()). $PSEErrorHandlingMsg") -Fatal
                }
            }
        }

        Add-InfoLog -Message "Start PI point creation."
        try {
            [OSIsoft.AF.Asset.AFDataReference]::CreateConfig($db, $hndl) > $null
        }
        catch {
            Start-Sleep -Seconds $WaitIntervalInSeconds
            Add-WarningLog -Message ("The first try of creating or updating PI Point data reference failed, try again.")
            $createConfigSecondTry = $true
            $db.UndoCheckOut($false);
            [OSIsoft.AF.Asset.AFDataReference]::CreateConfig($db, $hndl) > $null
        }
        Add-InfoLog -Message "Finished PI point creation."
		
        # Retrieve recalculation end time as the time when we start all analyses
        $recalculationEndTime = (ConvertFrom-AFRelativeTime -RelativeTime "*").ToString('u')

        # Enable all analyses
        Add-InfoLog -Message "Enabling all analyses of the AF database."
        $db.Analyses | ForEach-Object { $_.SetStatus([OSIsoft.AF.Analysis.AFStatus]::Enabled) }

        # Wait for all analyses to be in running state
        $attempt = 0
        $resetAnalysisCount = 10
        do {
            Start-Sleep -Seconds $WaitIntervalInSeconds

            $path = "Path:= '\\\\$($PISystem.Name)\\$($Database)\\*"
            $analysesStatus = $PISystem.AnalysisService.QueryRuntimeInformation($path, 'status id')

            # Potentially QueryRuntimeInformation returns analyses which have been deleted in AF 
            # but not fully cleaned up from PI Analysis Service.
            $inactiveAnalysesCount = $analysesStatus.Count - $db.Analyses.Count
            if ($analysesStatus.Count -gt 0) {
                $NotRunningAnalyses = $analysesStatus.Where( { $_[0].ToString() -notlike "Running" })
                if ($NotRunningAnalyses.Count -le $inactiveAnalysesCount) {
                    break
                }
            }

            # Periodically output a status message and try to reset error analyses
            if ((++$attempt % $RetryCountBeforeReporting) -eq 0) {
                Add-InfoLog -Message "Waiting on analyses to be enabled..."

                # Reset a number of analyses in error in order to expedite the process
                $analysesInError = $NotRunningAnalyses | Where-Object { 
                    $db.Analyses.Contains([System.guid]::New($_[1]))
                } | Select-Object -First $resetAnalysisCount | ForEach-Object { $db.Analyses[[System.guid]::New($_[1])] }
                $analysesInError | ForEach-Object { $_.SetStatus([OSIsoft.AF.Analysis.AFStatus]::Disabled) }
                $analysesInError | ForEach-Object { $_.SetStatus([OSIsoft.AF.Analysis.AFStatus]::Enabled) }
            }
        } while ($attempt -lt $MaxRetry) 

        if ($attempt -eq $MaxRetry) {
            Add-ErrorLog -Message ("Waiting on analyses to be enabled did not finish within " + 
                "$($WaitIntervalInSeconds * $MaxRetry) seconds. Please check the analysis status in" + 
                " PI System Explorer and troubleshoot any issues with PI Analysis Service.") -Fatal
        }

        Add-InfoLog -Message "Enabled all analyses of the AF database."
        Add-InfoLog -Message "Successfully added a new AF database, $($db.GetPath())."
    }

    # Build a new PI archive file if the existing archives do not cover the expected archive start time.
    # We assume there is no archive gap in PI Data Archive server.
    # Create an archive file covering additional 10 days so that tests have more flexibility in choosing event timestamp.
    $archiveStartTime = ConvertFrom-AFRelativeTime -RelativeTime "$DefaultPIDataStartTime-10d"
    $oldestArchive = (Get-PIArchiveFileInfo -Connection $PIDA -ErrorAction Stop | Sort-Object -Property StartTime)[0]

    if ($oldestArchive.StartTime -gt $archiveStartTime) {
        Add-InfoLog -Message "Adding a new archive file covering $archiveStartTime."

        $archiveName = $PIDA.CurrentRole.Name + '_' + $archiveStartTime.ToString("yyyy-MM-dd_HH-mm-ssZ") + ".arc"
        $NewPIArchiveParams = @{
            Name                = $archiveName
            StartTime           = $archiveStartTime
            EndTime             = $oldestArchive.StartTime
            Connection          = $PIDA
            UsePrimaryPath      = [switch]::Present
            WaitForRegistration = [switch]::Present
        }

        try {
            New-PIArchive @NewPIArchiveParams -ErrorAction Stop
        }
        catch {
            Add-ErrorLog -Message ($_ | Out-String) -Fatal                
        }

        if ( -not ((Get-PIArchiveInfo -Connection $PIDA).ArchiveFileInfo |
                Select-Object Path |
                Where-Object Path -Match $archiveName)) {
            Add-ErrorLog -Message "Creating the new archive failed." -Fatal
        }
    }
    
    # Run analysis recalculation if the existing PI data does not cover the minimal archive start time.
    $minimalArchivedDataStartTime = ConvertFrom-AFRelativeTime -RelativeTime $DefaultPIDataStartTime
    $val = Get-PIValue -PointName $SamplePIPoint -Time $minimalArchivedDataStartTime -Connection $PIDA
    if (-not $val.IsGood) {
        # Queue the recalculation on all analog analyses. 
        Add-InfoLog -Message "Start analysis recalculation, this may take a few minutes."
        $StartPIANRecalculationParams = @{
            Database = $db
            Query    = "TemplateName:'Demo Data - Analog*'"
            Start    = $minimalArchivedDataStartTime.ToString('u') 
            End      = $recalculationEndTime
        }
        Start-PIANRecalculation @StartPIANRecalculationParams 

        # Wait for the recalculation to finish
        $attempt = 0
        $recalcNotDone = $false
        $pointList = Get-PIPoint -Connection $PIDA -WhereClause pointsource:=$TestsPIPointSource |
        Where-Object { $_.Point.Name -match $CoveredByRecalcPIPointRegex }
        do {
            Start-Sleep -Seconds $WaitIntervalInSeconds

            $recalcNotDone = $false
            ForEach ($point in $pointList) {
                # Get the point value at 1 hour after the start time because some analyses are scheduled to run hourly.
                $pointValue = Get-PIValue -PIPoint $point -Time (
                    ConvertFrom-AFRelativeTime -RelativeTime "$DefaultPIDataStartTime+1h")

                # If a point value remains "No Data" (State: 248(Set: 0)), recalculation has not done yet.
                if (($pointValue.Value.StateSet -eq 0) -and ($pointValue.Value.State -eq 248)) {
                    $recalcNotDone = $true
                    break
                }
            }
            
            if ((++$attempt % $RetryCountBeforeReporting) -eq 0) {
                Add-InfoLog -Message "Waiting on analyses recalculation to finish..."
            }
        } while (($attempt -lt $MaxRetry) -and $recalcNotDone)

        if ($recalcNotDone) {
            Add-ErrorLog -Message ("Waiting on analysis recalculation did not finish within " +
                "$($WaitIntervalInSeconds * $attempt) seconds.  Please check the recalculation status in" + 
                " PI System Explorer and troubleshoot any issues with PI Analysis Service.") -Fatal
        }
        else {
            Add-InfoLog -Message "Finished analysis recalculation."
        }
    }   
}


function Start-PIANRecalculation {
    [CmdletBinding()]
    param(
        # Name of AF Database
        [Parameter(Mandatory = $true)]
        [OSIsoft.AF.AFDatabase]$Database,

        # Query string to search for target analyses to recalculate
        [string]$Query = "",

        # Start time of recalculation
        [string]$Start = $DefaultPIDataStartTime,

        # End time of recalculation
        [string]$End = "*",

        # Recalculation Mode
        [ValidateSet('DeleteExistingData', 'FillDataGaps')]
        [string]$Option = 'DeleteExistingData'
    )
    # Build an AFAnalysisSerach object to find all matching analyses
    $analysisSearch = New-Object OSIsoft.AF.Search.AFAnalysisSearch $Database, "", $Query

    # Get the total count of analyses that could be returned from the search query
    $count = $analysisSearch.GetTotalCount()

    if ($count -gt 0) {
        # Find all analyses that match the query string
        $analyses = $analysisSearch.FindAnalyses()

        $timeRange = New-Object OSIsoft.AF.Time.AFTimeRange $Start, $End
        Add-InfoLog -Message ("Queue $count analyses for recalculation from $($timeRange.StartTime) to $($timeRange.EndTime) " + 
            "in order to backfill data.")

        try {
            $Database.PISystem.AnalysisService.QueueCalculation($analyses, $timeRange, $Option) > $null
        }
        catch {
            Add-ErrorLog -Message ("Cannot connect to the PI Analysis Service on $($Database.PISystem.AnalysisService.Host). " +
                "Please make sure the service is running and Port $PIAnalysisServicePort is open.") -Fatal
        }
    } 
    else {
        Add-InfoLog -Message "No analyses found matching '$Query' in $Database."
    }
}


function Remove-TargetDatabase {
    [CmdletBinding()]
    param(
        # AF Server object
        [Parameter(Mandatory = $true)]
        [OSIsoft.AF.PISystem]$PISystem,

        # Name of AF Database
        [Parameter(Mandatory = $true)]
        [string]$Database,

        # PI Data Archive ClientChannel
        [Parameter(Mandatory = $true)]
        [OSIsoft.PI.Net.ClientChannel]$PIDA,

        # Switch to force cleanup
        [switch]$Force
    )
    $cleanupFlag = $true
    if (-not $Force) {
        $cleanupFlag = Get-UserBooleanInput -Message ("Execution will remove the target AF database, $Database, " + 
            "and all associated PI points, please confirm.")
    }

    if ($cleanupFlag) {
        try {
            $db = $PISystem.Databases[$Database]
            if ($db) {
                $db.Analyses | ForEach-Object { $_.SetStatus([OSIsoft.AF.Analysis.AFStatus]::Disabled) }
                $PISystem.AnalysisService.Refresh()
                Add-InfoLog -Message "Deleting the AF database, $($db.GetPath())."
                Remove-AFDatabase -Name $Database -AFServer $PISystem -ErrorAction Stop > $null
                Add-InfoLog -Message "Deleted the AF database."
            }
            else {
                Add-WarningLog -Message "Cannot find the AF database, $Database, on $PISystem."
            }

            # Delete all PI points with the test point source
            $pipoints = Get-PIPoint -WhereClause "pointsource:=$TestsPIPointSource" -Connection $PIDA
            if ($pipoints.Count -gt 0) {
                Add-InfoLog -Message "Deleting PI points with the pointsource of $TestsPIPointSource."
                $pipoints | ForEach-Object { Remove-PIPoint -Name $_.Point.Name -Connection $PIDA -ErrorAction Stop } 
                Add-InfoLog -Message "Deleted $($pipoints.Count) PI points."
            }
        }
        catch {
            Add-ErrorLog -Message ($_ | Out-String) -Fatal
        } 

        # Uninstall Visual Studio Build Tools
        if (Test-Path $VSBuildTools) {
            $p = Start-Process $VSBuildTools -ArgumentList "uninstall --installPath $BuildTools -q" -PassThru -Wait
            if ($p.ExitCode -ne 0) {
                Add-ErrorLog -Message ("Failed to uninstall Visual Studio Build Tools." + 
                    "Please run ""$VSBuildTools"" interactively and troubleshoot any issues.") -Fatal
            }
        }

        # Uninstall .NET Developer Pack
        if (Test-Path $DotNETDevPack) {
            $p = Start-Process $DotNETDevPack -ArgumentList "/uninstall /quiet /norestart" -PassThru -Wait
            if ($p.ExitCode -ne 0 -or (Test-Path $DotNETFrameworkDir)) {
                Add-ErrorLog -Message ("Failed to uninstall .NET Developer Pack." + 
                    "Please run ""$DotNETDevPack"" interactively and troubleshoot any issues.") -Fatal
            }
        }
    }
}
# SIG # Begin signature block
# MIIptgYJKoZIhvcNAQcCoIIppzCCKaMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCwFvkevk3KQOrn
# RnebAnqb9HmRiSEWMdX2N1aAwJzn0aCCDlgwggawMIIEmKADAgECAhAIrUCyYNKc
# TJ9ezam9k67ZMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0z
# NjA0MjgyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQDVtC9C0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0
# JAfhS0/TeEP0F9ce2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJr
# Q5qZ8sU7H/Lvy0daE6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhF
# LqGfLOEYwhrMxe6TSXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+F
# LEikVoQ11vkunKoAFdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh
# 3K3kGKDYwSNHR7OhD26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJ
# wZPt4bRc4G/rJvmM1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQay
# g9Rc9hUZTO1i4F4z8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbI
# YViY9XwCFjyDKK05huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchAp
# QfDVxW0mdmgRQRNYmtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRro
# OBl8ZhzNeDhFMJlP/2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IB
# WTCCAVUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+
# YXsIiGX0TkIwHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAC
# hjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAED
# MAgGBmeBDAEEATANBgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql
# +Eg08yy25nRm95RysQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFF
# UP2cvbaF4HZ+N3HLIvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1h
# mYFW9snjdufE5BtfQ/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3Ryw
# YFzzDaju4ImhvTnhOE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5Ubdld
# AhQfQDN8A+KVssIhdXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw
# 8MzK7/0pNVwfiThV9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnP
# LqR0kq3bPKSchh/jwVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatE
# QOON8BUozu3xGFYHKi8QxAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bn
# KD+sEq6lLyJsQfmCXBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQji
# WQ1tygVQK+pKHJ6l/aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbq
# yK+p/pQd52MbOoZWeE4wggegMIIFiKADAgECAhAF+BLmjK0L/V2GAXAB3YUeMA0G
# CSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjEwODE4MDAwMDAwWhcNMjIwOTAx
# MjM1OTU5WjCBhzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFDAS
# BgNVBAcTC1NhbiBMZWFuZHJvMRUwEwYDVQQKEwxPU0lzb2Z0LCBMTEMxFTATBgNV
# BAMTDE9TSXNvZnQsIExMQzEfMB0GCSqGSIb3DQEJARYQY29kZUBvc2lzb2Z0LmNv
# bTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMPAF+UnsJSNgFK50gTo
# DOfdHux5qtjHtERsI4XYHQVsSKqJYFwnb3XXZ8aMkikMzDVhcpfI+K7jY5XV0tgn
# DOP9iky81gD9Tw9zw3/QI/ktfQ8fmDMJxH++GiykbdC3bp97Cxbk5eIn3xdCNwQL
# h95KEo6hEUIwXMAdcDVpe9cG0LN3mtV533HnuWUKp2xCL1ERSjyjzOvIWuqWNaxG
# +cKEuY5bW6FVrvecmTFai53iqy4ezwG1Y+XRaIRi1DBLOszHPxNN76FzgbwJscmy
# UD997hZO3cMlCwVP5l4UFmnNyqbKKmKkxSy1n4wf+hkIE+RZkXZerOo+sPRygui5
# GKJVbnIZne4P2or80t+SpjRi+wJWigNy+ro5Z7fDjyQo05QxUE88ldOrsS8F7lvA
# XW8Y+7KOwdd784PksMKg+RNnR/+yOShzn8zN/Vk8+CdLEPi7Icc7/zUpZmC54SeK
# /ZzCcOSHupmerHhEUH1TLVEPSV8Hcdghi6heqcT1mqNllQroIerXtsKgG9WXKP6A
# NBNEkgi3mfwZMDWLa5k/QzvgYg49yOrp0OjePmcN2Z4vSZvW7TcVBkQKYQMTqXes
# uAVGY4bZJrZcFUC5OGWN9uHYn0YNL1yF4+ceWAR+Tj7KmjQcmmn7XGIJUTNGMRgV
# 10UnmFY/+AkPeDNgeFQtwmfHAgMBAAGjggIjMIICHzAfBgNVHSMEGDAWgBRoN+Dr
# tjv4XxGG+/5hewiIZfROQjAdBgNVHQ4EFgQULcTY6BDf60TGqg+HH7Za2RXGojQw
# GwYDVR0RBBQwEoEQY29kZUBvc2lzb2Z0LmNvbTAOBgNVHQ8BAf8EBAMCB4AwEwYD
# VR0lBAwwCgYIKwYBBQUHAwMwgbUGA1UdHwSBrTCBqjBToFGgT4ZNaHR0cDovL2Ny
# bDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0
# MDk2U0hBMzg0MjAyMUNBMS5jcmwwU6BRoE+GTWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIw
# MjFDQTEuY3JsMD4GA1UdIAQ3MDUwMwYGZ4EMAQQBMCkwJwYIKwYBBQUHAgEWG2h0
# dHA6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzCBlAYIKwYBBQUHAQEEgYcwgYQwJAYI
# KwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBcBggrBgEFBQcwAoZQ
# aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29k
# ZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcnQwDAYDVR0TAQH/BAIwADAN
# BgkqhkiG9w0BAQsFAAOCAgEAUp5Q9V4tJ9UYmd6+p11BQrzRaiP7vE4RJWl9ZzXM
# r3NqMBXzVaCs1o6B7ui9TvIqKRT3P+ZcwNvZT0esDZp5p4y0XlGrmCcMIfljtI+B
# DkSTSN0gFafu8xj6VLkeQAg2X6Xoyisv5rDFcqs17BoQoMDwtXhZjn0MiHFluzG+
# EKKk0X8lSrNwOcAkekBXKnPVhkTmx2GlICmaqBsNvFw4ATxGEXV8FnrcghaGsTI3
# PcxrhdHrV9Tw5SQXX+y+dCsLj+a+hH0Xd0UeNgKF89/BexaLNQ2O92Z8SCGngs3G
# fax7lCdRbSIR3BQw0I1kRu2H2M9t8JNtVe1oyufkAa860c09ttlUOgqHJW5W475E
# eU0LEpMiPjWR+2tsz7rQK3Kmpvdx0QtJ7/R4o57RtxjJhLRGI4YjI9alBgRm0MGk
# 1UtABBMyU9fAjFuMxlnVn1LBNrhpOlYtSfIO2Q9LQRZHygHp8h/AsL1N9KbYppq4
# GcPpT8AgZHKckJu8oV64nNSauhqm0jX+bkt6GKRyrkhwThAcwBdoDQG4A37ZKX64
# kS+t2X8IY2kBhIF8rZAozcxA0R3LyOeCiGb/AoJWTB8BwjHoNvr/44znxy9gDN1q
# c3OFGkV4hYegJHwYMvhmxRjF7cT9CHlBWeByQSaubTY43Ls3JlyuLcFhas5ANhYr
# XMYxghq0MIIasAIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2Vy
# dCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25p
# bmcgUlNBNDA5NiBTSEEzODQgMjAyMSBDQTECEAX4EuaMrQv9XYYBcAHdhR4wDQYJ
# YIZIAWUDBAIBBQCggZ4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYB
# BAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIDHqrao5V5cA
# LEVp2zKw1zJxo/s6Hk6RvI6oCqG3zc5zMDIGCisGAQQBgjcCAQwxJDAioSCAHmh0
# dHA6Ly90ZWNoc3VwcG9ydC5vc2lzb2Z0LmNvbTANBgkqhkiG9w0BAQEFAASCAgBp
# ZVxgOKPEmMtwYsGqWQ2q0dZfGFyR/PC5h5ETOfZXXcnfmtDXe3RDVjbm/AWsmDN4
# AUPlP/crFMves4FD7J21bHxE648qBP9CMDhit6iGYem5w5IJ4MEh9ShyKlyfnP4k
# szGAUQW6TjcypGRIaqQ5B8O4PsA6r7hYWCb1zgYIXES7hbXHUnZE1gAqBkKMsf5/
# qn+uNrjQKH6CW2fQayU6o1V3XveH4BRhe2nMsn5nMTGv04b3kGkCuWhnJlpNBp4+
# 17ZNVPzhLB5mP6QEEZsmaWnDWvKsgWKMfX6LmTXlFsIrQCj2kqt7CdHpQj4rK0t8
# 9G/JkiD2VJfKbZuftVdVtRcm06QDdUrR48yFOYYqTjPlno7D9HVlBv9ASjMMWZVH
# lWrwWdwZKP+tQj6YXL/Q2zWHx6VkCtgvfRVuA3/vzRz2MnrMbcQnNzsN0lUpxIp4
# 20Na/6H8s2YRYL1dvr/gWLzwIfHa52eBD9oxNwtDfnFlOW5VVn4uv4lLH1tWaAdu
# 7PPuhoe3EXEvnAKE7PfwS/+jLy4TYmq7KAM/oaq1I5jxTG4u9YDfOUKQCvJIFrF6
# HPyzdOyc79P976JzATVBRObI4qKLftDYib/VaePEqSzJ/dsk56wdYoqo2T9BHfTv
# OCmljWmHIU6IKCd5SAgsom9yKoMUE28p3qqv0Wq05aGCF2cwghdjBgorBgEEAYI3
# AwMBMYIXUzCCF08GCSqGSIb3DQEHAqCCF0Awghc8AgEDMQ8wDQYJYIZIAWUDBAIB
# BQAwdwYLKoZIhvcNAQkQAQSgaARmMGQCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFl
# AwQCAQUABCDzdP8KUcu7v6mlpa+h7ZGXnLVyarhCEgEnaRajyyJ7EwIQYkonecuC
# rE7J6K69zT48tBgPMjAyMjA4MDQxNDQ2MDJaoIITMTCCBsYwggSuoAMCAQICEAp6
# SoieyZlCkAZjOE2Gl50wDQYJKoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxFzAV
# BgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVk
# IEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTAeFw0yMjAzMjkwMDAw
# MDBaFw0zMzAzMTQyMzU5NTlaMEwxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjEkMCIGA1UEAxMbRGlnaUNlcnQgVGltZXN0YW1wIDIwMjIgLSAy
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuSqWI6ZcvF/WSfAVghj0
# M+7MXGzj4CUu0jHkPECu+6vE43hdflw26vUljUOjges4Y/k8iGnePNIwUQ0xB7pG
# bumjS0joiUF/DbLW+YTxmD4LvwqEEnFsoWImAdPOw2z9rDt+3Cocqb0wxhbY2rzr
# svGD0Z/NCcW5QWpFQiNBWvhg02UsPn5evZan8Pyx9PQoz0J5HzvHkwdoaOVENFJf
# D1De1FksRHTAMkcZW+KYLo/Qyj//xmfPPJOVToTpdhiYmREUxSsMoDPbTSSF6IKU
# 4S8D7n+FAsmG4dUYFLcERfPgOL2ivXpxmOwV5/0u7NKbAIqsHY07gGj+0FmYJs7g
# 7a5/KC7CnuALS8gI0TK7g/ojPNn/0oy790Mj3+fDWgVifnAs5SuyPWPqyK6BIGtD
# ich+X7Aa3Rm9n3RBCq+5jgnTdKEvsFR2wZBPlOyGYf/bES+SAzDOMLeLD11Es0Md
# I1DNkdcvnfv8zbHBp8QOxO9APhk6AtQxqWmgSfl14ZvoaORqDI/r5LEhe4ZnWH5/
# H+gr5BSyFtaBocraMJBr7m91wLA2JrIIO/+9vn9sExjfxm2keUmti39hhwVo99Rw
# 40KV6J67m0uy4rZBPeevpxooya1hsKBBGBlO7UebYZXtPgthWuo+epiSUc0/yUTn
# gIspQnL3ebLdhOon7v59emsCAwEAAaOCAYswggGHMA4GA1UdDwEB/wQEAwIHgDAM
# BgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMCAGA1UdIAQZMBcw
# CAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAfBgNVHSMEGDAWgBS6FtltTYUvcyl2mi91
# jGogj57IbzAdBgNVHQ4EFgQUjWS3iSH+VlhEhGGn6m8cNo/drw0wWgYDVR0fBFMw
# UTBPoE2gS4ZJaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3Rl
# ZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGluZ0NBLmNybDCBkAYIKwYBBQUHAQEE
# gYMwgYAwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBYBggr
# BgEFBQcwAoZMaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGluZ0NBLmNydDANBgkqhkiG9w0B
# AQsFAAOCAgEADS0jdKbR9fjqS5k/AeT2DOSvFp3Zs4yXgimcQ28BLas4tXARv4QZ
# iz9d5YZPvpM63io5WjlO2IRZpbwbmKrobO/RSGkZOFvPiTkdcHDZTt8jImzV3/ZZ
# y6HC6kx2yqHcoSuWuJtVqRprfdH1AglPgtalc4jEmIDf7kmVt7PMxafuDuHvHjiK
# n+8RyTFKWLbfOHzL+lz35FO/bgp8ftfemNUpZYkPopzAZfQBImXH6l50pls1klB8
# 9Bemh2RPPkaJFmMga8vye9A140pwSKm25x1gvQQiFSVwBnKpRDtpRxHT7unHoD5P
# ELkwNuTzqmkJqIt+ZKJllBH7bjLx9bs4rc3AkxHVMnhKSzcqTPNc3LaFwLtwMFV4
# 1pj+VG1/calIGnjdRncuG3rAM4r4SiiMEqhzzy350yPynhngDZQooOvbGlGglYKO
# KGukzp123qlzqkhqWUOuX+r4DwZCnd8GaJb+KqB0W2Nm3mssuHiqTXBt8CzxBxV+
# NbTmtQyimaXXFWs1DoXW4CzM4AwkuHxSCx6ZfO/IyMWMWGmvqz3hz8x9Fa4Uv4px
# 38qXsdhH6hyF4EVOEhwUKVjMb9N/y77BDkpvIJyu2XMyWQjnLZKhGhH+MpimXSuX
# 4IvTnMxttQ2uR2M4RxdbbxPaahBuH0m3RFu0CAqHWlkEdhGhp3cCExwwggauMIIE
# lqADAgECAhAHNje3JFR82Ees/ShmKl5bMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0y
# MjAzMjMwMDAwMDBaFw0zNzAzMjIyMzU5NTlaMGMxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBH
# NCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDGhjUGSbPBPXJJUVXHJQPE8pE3qZdRodbSg9GeTKJt
# oLDMg/la9hGhRBVCX6SI82j6ffOciQt/nR+eDzMfUBMLJnOWbfhXqAJ9/UO0hNoR
# 8XOxs+4rgISKIhjf69o9xBd/qxkrPkLcZ47qUT3w1lbU5ygt69OxtXXnHwZljZQp
# 09nsad/ZkIdGAHvbREGJ3HxqV3rwN3mfXazL6IRktFLydkf3YYMZ3V+0VAshaG43
# IbtArF+y3kp9zvU5EmfvDqVjbOSmxR3NNg1c1eYbqMFkdECnwHLFuk4fsbVYTXn+
# 149zk6wsOeKlSNbwsDETqVcplicu9Yemj052FVUmcJgmf6AaRyBD40NjgHt1bicl
# kJg6OBGz9vae5jtb7IHeIhTZgirHkr+g3uM+onP65x9abJTyUpURK1h0QCirc0PO
# 30qhHGs4xSnzyqqWc0Jon7ZGs506o9UD4L/wojzKQtwYSH8UNM/STKvvmz3+Drhk
# Kvp1KCRB7UK/BZxmSVJQ9FHzNklNiyDSLFc1eSuo80VgvCONWPfcYd6T/jnA+bIw
# pUzX6ZhKWD7TA4j+s4/TXkt2ElGTyYwMO1uKIqjBJgj5FBASA31fI7tk42PgpuE+
# 9sJ0sj8eCXbsq11GdeJgo1gJASgADoRU7s7pXcheMBK9Rp6103a50g5rmQzSM7TN
# sQIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUuhbZ
# bU2FL3MpdpovdYxqII+eyG8wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4c
# D08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUF
# BwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEG
# CCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAX
# MAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBAH1ZjsCT
# tm+YqUQiAX5m1tghQuGwGC4QTRPPMFPOvxj7x1Bd4ksp+3CKDaopafxpwc8dB+k+
# YMjYC+VcW9dth/qEICU0MWfNthKWb8RQTGIdDAiCqBa9qVbPFXONASIlzpVpP0d3
# +3J0FNf/q0+KLHqrhc1DX+1gtqpPkWaeLJ7giqzl/Yy8ZCaHbJK9nXzQcAp876i8
# dU+6WvepELJd6f8oVInw1YpxdmXazPByoyP6wCeCRK6ZJxurJB4mwbfeKuv2nrF5
# mYGjVoarCkXJ38SNoOeY+/umnXKvxMfBwWpx2cYTgAnEtp/Nh4cku0+jSbl3ZpHx
# cpzpSwJSpzd+k1OsOx0ISQ+UzTl63f8lY5knLD0/a6fxZsNBzU+2QJshIUDQtxMk
# zdwdeDrknq3lNHGS1yZr5Dhzq6YBT70/O3itTK37xJV77QpfMzmHQXh6OOmc4d0j
# /R0o08f56PGYX/sr2H7yRp11LB4nLCbbbxV7HhmLNriT1ObyF5lZynDwN7+YAN8g
# Fk8n+2BnFqFmut1VwDophrCYoCvtlUG3OtUVmDG0YgkPCr2B2RP+v6TR81fZvAT6
# gt4y3wSJ8ADNXcL50CN/AAvkdgIm2fBldkKmKYcJRyvmfxqkhQ/8mJb2VVQrH4D6
# wPIOK+XW+6kvRBVK5xMOHds3OBqhK/bt1nz8MIIFsTCCBJmgAwIBAgIQASQK+x44
# C4oW8UtxnfTTwDANBgkqhkiG9w0BAQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UE
# ChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYD
# VQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMjIwNjA5MDAwMDAw
# WhcNMzExMTA5MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNl
# cnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdp
# Q2VydCBUcnVzdGVkIFJvb3QgRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQC/5pBzaN675F1KPDAiMGkz7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QN
# xDAf8xukOBbrVsaXbR2rsnnyyhHS5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DC
# srp1mWpzMpTREEQQLt+C8weE5nQ7bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTr
# BcZe7FsavOvJz82sNEBfsXpm7nfISKhmV1efVFiODCu3T6cw2Vbuyntd463JT17l
# Necxy9qTXtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WC
# QTLX2wRzKm6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1
# EVgX9yRcRo9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KS
# Op493ADkRSWJtppEGSt+wJS00mFt6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAs
# QWCqsWMYRJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUO
# UlFHdL4mrLZBdd56rF+NP8m800ERElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtv
# sauGi0/C1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t9dmpsh3lGwIDAQABo4IBXjCC
# AVowDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4c
# D08wHwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQD
# AgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHkGCCsGAQUFBwEBBG0wazAkBggrBgEF
# BQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRw
# Oi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0Eu
# Y3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9E
# aWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIw
# CwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBDAUAA4IBAQCaFgKlAe+B+w20WLJ4ragj
# GdlzN9pgnlHXy/gvQLmjH3xATjM+kDzniQF1hehiex1W4HG63l7GN7x5XGIATfhJ
# elFNBjLzxdIAKicg6okuFTngLD74dXwsgkFhNQ8j0O01ldKIlSlDy+CmWBB8U46f
# RckgNxTA7Rm6fnc50lSWx6YR3zQz9nVSQkscnY2W1ZVsRxIUJF8mQfoaRr3esOWR
# RwOsGAjLy9tmiX8rnGW/vjdOvi3znUrDzMxHXsiVla3Ry7sqBiD5P3LqNutFcpJ6
# KXsUAzz7TdZIcXoQEYoIdM1sGwRc0oqVA3ZRUFPWLvdKRsOuECxxTLCHtic3RGBE
# MYIDdjCCA3ICAQEwdzBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQs
# IEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEy
# NTYgVGltZVN0YW1waW5nIENBAhAKekqInsmZQpAGYzhNhpedMA0GCWCGSAFlAwQC
# AQUAoIHRMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUx
# DxcNMjIwODA0MTQ0NjAyWjArBgsqhkiG9w0BCRACDDEcMBowGDAWBBSFCPOGUVyz
# 0wd9trS3wH8bSl5B3jAvBgkqhkiG9w0BCQQxIgQgZYS3kp/UrGAH3ocXonK4IC/C
# B5Q9lqfpL/ZZJ8eVxTswNwYLKoZIhvcNAQkQAi8xKDAmMCQwIgQgnaaQFcNJxsGJ
# eEW6NYKtcMiPpCk722q+nCvSU5J55jswDQYJKoZIhvcNAQEBBQAEggIAI217acRH
# xZ8Jhfqbkegfa/NPFJv9SOb4qNpRmGvuXG51LWmN59BnUX+SbIIOZ2S+JWGT+Wl9
# H/7WPtonMvowTaYJThZtcPdqmYFfibeydXb2Td2VzNGzT8PNKgk59CcXC4xaidc7
# SghHNuTAjMKA0QiaBVNwFM/OdlAoJBlQRQ1iMMuMa3udN9dvwO4M1p08ky7e91RF
# oTpxrDSlhVjgWHA3GxdeHQoEwIn96na0iT3G+pzBBW+SlWTHdA1mJJOzGBk/3Otb
# r7zbcEw6AigunoeLrcVFSieKcFgNPp6W8T1zwBYrmuGIAUlphbxzZvgvAZGHQ6+A
# u8yMbrfI7Sy/Bf10HBQK0cpkmtqnsFK0NyLVj8oFJTcMMeTmqiRJTW8ttCFehWuS
# zY4fseekJnd8iTxy+ctqaBzVMst8turninIMR+a0TOCeb4Ik2Js87tQukCShs19/
# MC3lpj/sh3pEP83A1hkgdTNbJGRHyuN+Y1Rzp9NJ4WxcgR+GkToUE4wjfp+oJK/p
# 7LYMVnljyCWqOtb44m3zHYfMFiljEUGlSHRj7nFCXtsLvOPJbfEdzJiW4JV4m7uf
# SJh0n1Hg12lfZ/mclYLPVQLXwkOOEJ5LX3tGlaH3xgO2GoPb5/kRltwrsKdewALa
# XsY32tmbsrpHnHrzDHAE3Ysjf3XlO4bNSf8=
# SIG # End signature block
