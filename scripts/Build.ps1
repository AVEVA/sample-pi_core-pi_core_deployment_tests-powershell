#requires -version 4.0
<##############################################################################

Functions for building the PSD Tests

###############################################################################>

function Install-BuildTools {
    [CmdletBinding()]
    param()
    if (-not (Test-MSBuildVersionPresent)) {
        if (-not (Test-Path $VSBuildTools)) {
            New-FolderIfNotExists($TempDir)

            Add-InfoLog -Message "Downloading $VSBuildToolsFileName."
            Invoke-WebRequest $VSBuildToolsUri -OutFile $VSBuildTools
        }

        # Install Visual Studio Build Tools
        $p = Start-Process $VSBuildTools -ArgumentList "-q" -PassThru -Wait
        if ($p.ExitCode -ne 0 -or -not (Test-MSBuildVersionPresent)) {
            Add-ErrorLog -Message ("Failed to install MSBuild. " + 
                "Please run ""$VSBuildTools"" interactively and troubleshoot any issues.") -Fatal
        }

        Add-InfoLog -Message "Installed MSBuild successfully."
    }
}


function Get-LatestVisualStudioRoot {
    [CmdletBinding()]
    param()
    # Try to use vswhere to find the latest version of Visual Studio.
    if (Test-Path $VsWhereExe) {
        $installationPath = & $VsWhereExe -latest -prerelease -property installationPath
        if ($installationPath) {
            Add-VerboseLog -Message "Found Visual Studio installed at `"$installationPath`"."
        }
        
        return $installationPath
    }    
}


function Get-MSBuildRoot {
    [CmdletBinding()]
    param(    )
    # Assume msbuild is installed with Visual Studio
    $VisualStudioRoot = Get-LatestVisualStudioRoot
    if ($VisualStudioRoot -and (Test-Path $VisualStudioRoot)) {
        $MSBuildRoot = Join-Path $VisualStudioRoot 'MSBuild'
    }

    # Assume msbuild is installed with Build Tools
    if (-not $MSBuildRoot -or -not (Test-Path $MSBuildRoot)) {
        $MSBuildRoot = Join-Path $BuildTools 'MSBuild'
    }

    # If not found before
    if (-not $MSBuildRoot -or -not (Test-Path $MSBuildRoot)) {
        # Assume msbuild is installed at default location
        $MSBuildRoot = Join-Path ${env:ProgramFiles(x86)} 'MSBuild'
    }

    $MSBuildRoot
}


function Get-MSBuildExe {
    [CmdletBinding()]
    param(
        [int]$MSBuildVersion,
        [switch]$TestOnly
    )
    if (-not $Script:MSBuildExe) {
        # Get the highest msbuild version if version was not specified
        if (-not $MSBuildVersion) {
            Get-MSBuildExe -MSBuildVersion $DefaultMSBuildVersion -TestOnly:$TestOnly
            return
        }

        $MSBuildRoot = Get-MSBuildRoot
        $MSBuildExe = Join-Path $MSBuildRoot 'Current\bin\msbuild.exe'

        if (-not (Test-Path $MSBuildExe)) {
            $MSBuildExe = Join-Path $MSBuildRoot "${MSBuildVersion}.0\bin\msbuild.exe"
        }

        if (Test-Path $MSBuildExe) {
            Add-VerboseLog -Message "Found MSBuild.exe at `"$MSBuildExe`"."
            $Script:MSBuildExe = $MSBuildExe
        } 
        elseif (-not $TestOnly) {
            Add-ErrorLog -Message ("Cannot find MSBuild.exe. Please download and install the Visual Studio Build Tools " +
                "from $VSBuildToolsUri.") -Fatal
        }
    }
}


function Test-MSBuildVersionPresent {
    [CmdletBinding()]
    param(
        [int]$MSBuildVersion = $DefaultMSBuildVersion
    )
    Get-MSBuildExe $MSBuildVersion -TestOnly

    $Script:MSBuildExe -and (Test-Path $Script:MSBuildExe)
}

function Build-TestSolution {
    [CmdletBinding()]
    param()
    if (-not $Script:MSBuildExe) {
        Get-MSBuildExe
    }
    
    (& $Script:MSBuildExe /nologo $Solution /t:rebuild /p:Configuration=$BuildConfiguration`;Platform=$BuildPlatform) |
    Select-String -Pattern "Build succeeded|Build failed" -Context 0, 100 | Out-String | 
    ForEach-Object { $_.Trim().substring(2) } | Add-InfoLog
    
    if ($LASTEXITCODE) {
        Add-ErrorLog -Message "Build failed @""$Solution""." -Fatal
    }
}

function Build-Tests {
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

    Add-InfoLog -Message "Build the test solution."
    Build-TestSolution

    Copy-Run-Config
}

