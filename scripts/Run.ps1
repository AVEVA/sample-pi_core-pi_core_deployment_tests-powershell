<#
.SYNOPSIS
    Runs the full work flow of OSIsoft PI System Deployment Tests

.DESCRIPTION
    The work flow consists of following steps:
        Load test configuration,
        Test the connection to servers,
        Create the target Wind Farm AF database if needed,
        Install build tools if missing, 
        Build test solution, 
        Execute the test suite,
        Optionally remove the Wind Farm PI database.

.PARAMETER Preliminary
    Switch to build and run the PreliminaryCheck tests

.PARAMETER Setup
    Switch to set up the target AF database

.PARAMETER Testing
    Switch to build and run all tests

.PARAMETER TestClass
    Name of the xUnit test class to run.  If set, the script will run all tests in the class. The Testing switch is optional.

.PARAMETER TestName
    Name of the xUnit test to run.  If set, only the single test will be run. The TestClass parameter is required.
    
.PARAMETER Cleanup
    Switch to remove the test environment

.PARAMETER Force
    Switch to suppress confirmation prompts

.EXAMPLE
.\run.ps1
Run the full work flow

.EXAMPLE
.\run.ps1 -f
Run the full work flow without confirmation prompts

.EXAMPLE
.\run.ps1 -p
Set up the target AF Database

.EXAMPLE
.\run.ps1 -b
Build the test code - does the same steps as setup, along with the actual build.

.EXAMPLE
.\run.ps1 -s
Set up the target AF Database

.EXAMPLE
.\run.ps1 -s -f
Set up the target AF Database without confirmation prompts (setup '-s' no longer builds the code)

.EXAMPLE
.\run.ps1 -t
Run xUnit tests 

.EXAMPLE
.\run.ps1 -t -f
Run xUnit tests without confirmation prompts

.EXAMPLE
.\run.ps1 -TestClass "MyTestClass"
Run a specific xUnit test class

.EXAMPLE
.\run.ps1 -TestClass "MyTestClass"
Run a specific xUnit test class

.EXAMPLE
.\run.ps1 -TestClass "MyTestClass" -f
Run a specific xUnit test class without confirmation prompts

.EXAMPLE
.\run.ps1 -TestClass "MyTestClass" -TestName "MyTest"
Run a specific xUnit test

.EXAMPLE
.\run.ps1 -TestClass "MyTestClass" -TestName "MyTest" -f
Run a specific xUnit test without confirmation prompts

.EXAMPLE
.\run.ps1 -c
Clean up all test related PI/AF components

.EXAMPLE
.\run.ps1 -c -f
Clean up all test related PI/AF components without confirmation prompts
#>
#requires -version 4.0
[CmdletBinding()]
Param (
    [Alias('p')]
    [switch]$Preliminary,

    [Alias('s')]
    [switch]$Setup,
    
    [Alias('t')]
    [switch]$Testing,

    [String]$TestClass = '',

    [String]$TestName = '',

    [Alias('c')]
    [switch]$Cleanup,

    [Alias('f')]
    [switch]$Force,

    [Alias('b')]
    [switch]$Build
)

$MinimumOSIPSVersion = New-Object System.Version("2.2.2.0")
$OSIPSModule = Get-Module -ListAvailable -Name OSIsoft.PowerShell
$OSIPSVersion = (Get-Item $OSIPSModule.Path).VersionInfo.ProductVersion
if ((-not $OSIPSModule) -or ($OSIPSVersion -lt $MinimumOSIPSVersion)) {
    Write-Error -Message ("The script requires PI AF Client and PowerShell Tools for the PI System with a minimum " + 
        "version of 2018 SP3, please upgrade PI software and try again." + [environment]::NewLine) -ErrorAction Stop
}

. "$PSScriptRoot\common.ps1"
. "$PSScriptRoot\build.ps1"

Add-InfoLog -Message "Start OSIsoft PI System Deployment Tests script."

Add-InfoLog -Message "Load PI System settings."
$config = Read-PISystemConfig -Force:$Force

Add-InfoLog -Message "Test connection to the specified PI Data Archive, $($config.PIDataArchive)."
$PIDAConfig = Get-PIDataArchiveConnectionConfiguration -Name $config.PIDataArchive
if (-not $PIDAConfig) {
    Add-ErrorLog -Message "Could not retrieve PI Data Archive connection information from $($config.PIDataArchive)" -Fatal
}

$PIDA = Connect-PIDataArchive -PIDataArchiveConnectionConfiguration $PIDAConfig -ErrorAction Stop

Add-InfoLog -Message "Test connection to the specified AF server, $($config.AFServer)."
$PISystems = New-Object OSIsoft.AF.PISystems
$PISystem = $PISystems[$config.AFServer]
if (-not $PISystem) {
    Add-ErrorLog -Message "Cannot find the specified AF Server, $($config.AFServer)." -Fatal
}

# If testing related parameters are specified, set runTests flag to true.
$runTests = ($Testing.IsPresent -or ($TestClass -ne '') -or ($TestName -ne '')) -and -not $Preliminary.IsPresent

# Three major steps in the work flow are Setup, Testing and Cleanup.  One may choose to run one or more steps.
# If no particular switch is specified, the script will run all steps.
$runAll = -not ($Preliminary -or $Setup -or $runTests -or $Cleanup)

# Run PreliminaryChecks xUnit tests
if ($Preliminary -or $runAll) {
    Add-InfoLog -Message "Setup xUnit tests."
    Setup-Tests

    Add-InfoLog -Message "Run PreliminaryChecks xUnit tests."
    Start-PrelimTesting
}

# Build tests
if ($Build) {
    Add-InfoLog -Message "Build xUnit tests."
    Build-Tests
}

# Run setup steps
if ($Setup -or $runAll) {
    Add-InfoLog -Message "Set up the target AF database."
    $SetTargetDatabaseParams = @{
        PISystem = $PISystem
        Database = $config.AFDataBase
        PIDA     = $PIDA
        Force    = $Force
    }
    Set-TargetDatabase @SetTargetDatabaseParams
}

# Run xUnit tests
if ($runTests -or $runAll) {
    Add-InfoLog -Message "Test connection to the target AF database, $($config.AFDatabase), on $($config.AFServer)."
    $TargetDatabase = $PISystem.Databases[$config.AFDatabase]
    if (-not $TargetDatabase) {
        Add-ErrorLog -Message ("Cannot find the specified AF database, $($config.AFDatabase)," + 
            " on $($config.AFServer).") -Fatal
    }

    if (-not $runAll) {
        Add-InfoLog -Message "Build xUnit tests."
        Setup-Tests
	}

    if ($TestName -ne '' -and $TestClass -ne '') {
        Add-InfoLog -Message "Run xUnit test '$TestName'."
        Start-Testing -TestClassName "$TestClass" -TestName "$TestName"
    }
    elseif ($TestName -eq '' -and $TestClass -ne '') {
        Add-InfoLog -Message "Run xUnit test class '$TestClass'."
        Start-Testing -TestClassName "$TestClass"
    }
    elseif ($TestName -eq '' -and $TestClass -eq '') {
        Add-InfoLog -Message "Run xUnit tests."
        Start-Testing
    }
    else {
        Add-ErrorLog -Message "Incorrect usage for test runs. Correct usage: '.\run.ps1 -t (Optional)-TestClass 'MyTestClass' (Optional, Requires TestClass)-TestName 'MyTest' (Optional)-f'" -Fatal
    }
}

# Run cleanup steps
if ($Cleanup -or $runAll) {
    Add-InfoLog -Message "Remove all test related components."
    $RemoveTargetDatabaseParams = @{
        PISystem = $PISystem
        Database = $config.AFDataBase
        PIDA     = $PIDA
        Force    = $Force
    }
    Remove-TargetDatabase @RemoveTargetDatabaseParams
}

Disconnect-PIDataArchive -Connection $PIDA > $null

Add-InfoLog -Message "OSIsoft PI System Deployment Tests script finished."
# SIG # Begin signature block
# MIIptgYJKoZIhvcNAQcCoIIppzCCKaMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB2TqJCRqZqvhhy
# YicRsjIelaQMPECscb3nJxnbQUhj+qCCDlgwggawMIIEmKADAgECAhAIrUCyYNKc
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
# BAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJwGJ6TLRhML
# 6nUeJ87oFehBRXXKYQ4h0dJhzuBPNOlPMDIGCisGAQQBgjcCAQwxJDAioSCAHmh0
# dHA6Ly90ZWNoc3VwcG9ydC5vc2lzb2Z0LmNvbTANBgkqhkiG9w0BAQEFAASCAgBd
# G+e7lUishemsM0fpaSll+nFtW742Mc9CuaNqcJcKmAPCrBHl6i5qOlW0ut3gJw9B
# 9DIoe44sa239YtXjLNsrENblyouy2U+Oo3EmImGPFjymbCUM20v2CYjmJL2s/lWS
# 6IGFnDy0QP8ByJSQ+CViYvcKDW3a9OTz0tW5cYce3XYa28eC4+YH+IihqnJPMZFm
# z2eWcjPlZvRWS78ieiNQiYmLSJfJcdSmZ7kYdW0KccA9sDV+1sImoc5Ja88dLuNg
# YPIbDMk1cSlUbrv79DIUrwe6bYwbgDfi2FEaYRcGg+njyYO6reAqQWhXBaySvZ5y
# xjiv4J7RVMp0KU1Fc4c7C7t+QiHp09oopzJ3mIPkA5AdYQIsS5ypxzmhbfX/Dv3s
# z4J/EjI+zamwNgD2a2fWCURkB+Uwnn2Jge7KmNJT6yxgYFDZKiN5AvTJ52QuINyX
# NHF/TmsDh3JYYIkF8vwtL0BGbCQMs+/97sJx5AeTSTjiDKXmcMiRzygRJxZERIf2
# C4hHBbcVIzxF8H9G4BLf9rked6CKJisE8IEbwp22yCO50eYKHRk/lJmx7C1QeyT1
# oXfxWkV+hy+lc8Jm51CqAx9Ur2uankGDqs4xiDEO+a/JUx7gNzR3ZFovDAEQRzzX
# SLbETzVCkhgCsMbQ6ThWCp1Fynrx4Ldi8HBxOtpVl6GCF2cwghdjBgorBgEEAYI3
# AwMBMYIXUzCCF08GCSqGSIb3DQEHAqCCF0Awghc8AgEDMQ8wDQYJYIZIAWUDBAIB
# BQAwdwYLKoZIhvcNAQkQAQSgaARmMGQCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFl
# AwQCAQUABCCl3HxOwFZZQqxw0+tOlAaQMXUKyHJehTXUlQvMTHpMQwIQEKiqG7lX
# 4a7ydNjIwKy0GRgPMjAyMjA3MDcxNTQyMDBaoIITMTCCBsYwggSuoAMCAQICEAp6
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
# DxcNMjIwNzA3MTU0MjAwWjArBgsqhkiG9w0BCRACDDEcMBowGDAWBBSFCPOGUVyz
# 0wd9trS3wH8bSl5B3jAvBgkqhkiG9w0BCQQxIgQgpzFFqYzSuTYdmzqRkY3ScvFd
# rx1D+Zix/ihOIU641ggwNwYLKoZIhvcNAQkQAi8xKDAmMCQwIgQgnaaQFcNJxsGJ
# eEW6NYKtcMiPpCk722q+nCvSU5J55jswDQYJKoZIhvcNAQEBBQAEggIAgHwpG8+s
# 8NOnti+AecArTQRVyT46dq2IHsMo+hAcIZm+QtFBYCN9jdlZq2QLYuQdzkvB9PZZ
# y5+cPr18cQ2rjsB5QexvcmKxiCqQUVAdEp99yk2crerdhRzCa8i75cbun7SoGh9C
# xMUX/291N6JaPxVmnXE7Rl00z0sy75Zic7TXMxEWah/xvbpL3PaxEOHkzYH0H/vX
# osgZi0S2aOwP0kf6wRTOSkzGYIM/wGzb551fS1dWJcTT3z6MQgIrQQ04HyyH9sKu
# DLbftc4MdrWx9npXllPpXW670jMDTBXd09ZMKonl6TAf9QYCiWQBf0Ale68qNho5
# H4Hp+KSChkivLW95xxNCDOqCQG1A7s0P9D8kq0oPsaq7PKNugpafBjo39hqt6Bpu
# NfxTC6EQI+y0NUT8Dw0tXyU1m6HhMOOBtOsqo8LAyZcXsMU2cqA/ktuyfyYAhQbf
# Mz4kwsTxij9aCLdTtADkElqTU1hCHSAhNt2ajXDyC0zZrkOZB69RtHbxxnmvY7q4
# /cSAlNqGhguBMfOKwjTpkMERBnsnXLzSOisKDtW8lHmuvVMpy2T7SbDlb4iN/kbI
# N3ei1avPP7WEeK+q4pZmu9Zk5itf1VmShOoJJYYHepHsdoJLMKcU9GqCrVbGFm/f
# lzqkhlL/mG0Gv01/hw1G5fnvVAE4wqgZlVA=
# SIG # End signature block
