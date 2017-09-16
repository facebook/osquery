﻿#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

param(
  [string] $startupArgs = "",
  [switch] $install = $false,
  [switch] $uninstall = $false,
  
  [switch] $start = $false,
  [switch] $stop = $false,
  
  [switch] $help = $false,
  [switch] $debug = $false,

  [switch] $install_wel_manifest = $false,
  [switch] $uninstall_wel_manifest = $false
)

$kServiceName = "osqueryd"
$kServiceDescription = "osquery daemon service"
$kServiceBinaryPath = Resolve-Path ([System.IO.Path]::Combine($PSScriptRoot, '..', 'osquery', 'osqueryd', 'osqueryd.exe'))
$windowsEvengLogManifest = Join-Path $PSScriptRoot 'osquery.man'

# Adapted from http://www.jonathanmedd.net/2014/01/testing-for-admin-privileges-in-powershell.html
function Test-IsAdmin {
  return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator"
  )
}

function Do-Help {
  $programName = (Get-Item $PSCommandPath ).Name
  
  Write-Host "Usage: $programName (-install|-uninstall|-start|-stop|-help)" -foregroundcolor Yellow
  Write-Host ""
  Write-Host "  Only one of the following options can be used. Using multiple will result in "
  Write-Host "  options being ignored."
  Write-Host "    -install                  Install the osqueryd service"
  Write-Host "    -startupArgs              Specifies additional arguments for the service (only used with -install)"
  Write-Host "    -uninstall                Uninstall the osqueryd service"
  Write-Host "    -start                    Start the osqueryd service"
  Write-Host "    -stop                     Stop the osqueryd service"
  Write-Host "    -install_wel_manifest     Installs the Windows Event Log manifest"
  Write-Host "    -uninstall_wel_manifest   Uninstalls the Windows Event Log manifest"
  Write-Host ""
  Write-Host "    -help                     Shows this help screen"
  
  Exit 1
}

function Do-Service {
  if (-not (Test-Path $kServiceBinaryPath)) {
    Write-Host "'$kServiceBinaryPath' is not a valid file. Did you build the osquery daemon?" -foregroundcolor Red
    Exit -1
  }
  
  $osquerydService = Get-WmiObject -Class Win32_Service -Filter "Name='$kServiceName'"
  
  if ($install) {
    if ($osquerydService) {
      Write-Host "'$kServiceName' is already installed." -foregroundcolor Yellow
      Exit 1
    } else {
      New-Service -BinaryPathName "$kServiceBinaryPath $startupArgs" `
                  -Name $kServiceName `
                  -DisplayName $kServiceName `
                  -Description $kServiceDescription `
                  -StartupType Automatic
      Write-Host "Installed '$kServiceName' system service." -foregroundcolor Cyan
      Exit 0
    }
  } elseif ($uninstall) {
    if ($osquerydService) {
      Stop-Service $kServiceName
      
      Write-Host "Found '$kServiceName', stopping the system service..."
      
      Start-Sleep -s 5
      
      Write-Host "System service should be stopped."
      
      $osquerydService.Delete()
      Write-Host "System service '$kServiceName' uninstalled." -foregroundcolor Cyan
      
      Exit 0
    } else {
      Write-Host "'$kServiceName' is not an installed system service." -foregroundcolor Yellow
      Exit 1
    }
  } elseif ($start) {
    if ($osquerydService) {
      Start-Service $kServiceName
      Write-Host "'$kServiceName' system service is started." -foregroundcolor Cyan
    } else {
      Write-Host "'$kServiceName' is not an installed system service." -foregroundcolor Yellow
      Exit 1
    }
  } elseif ($stop) {
    if ($osquerydService) {
      Stop-Service $kServiceName
      Write-Host "'$kServiceName' system service is stopped." -foregroundcolor Cyan
    } else {
      Write-Host "'$kServiceName' is not an installed system service." -foregroundcolor Yellow
      Exit 1      
    }
  } elseif ($install_wel_manifest) {
    wevtutil im $windowsEvengLogManifest
    if ($?) {
      Write-Host "The Windows Event Log manifest has been successfully installed." -foregroundcolor Cyan
    } else {
      Write-Host "Failed to install the Windows Event Log manifest." -foregroundcolor Yellow
    }

  } elseif ($uninstall_wel_manifest) {
    wevtutil um $windowsEvengLogManifest
    if ($?) {
      Write-Host "The Windows Event Log manifest has been successfully uninstalled." -foregroundcolor Cyan
    } else {
      Write-Host "Failed to uninstall the Windows Event Log manifest." -foregroundcolor Yellow
    }
  } else {
    Write-Host "Invalid state: this should not exist!" -foregroundcolor Red
    Exit -1
  }
}

function Main {
  if (-not (Test-IsAdmin)) {
    Write-Host "Please run this script with Admin privileges!" -foregroundcolor Red
    Exit -1
  }
  
  if ($help) {
    Do-Help
  } elseif ($debug) {
    $osquerydExists = Test-Path $kServiceBinaryPath
    
    Write-Host "Service Information" -foregroundcolor Cyan
    Write-Host "  kServiceName       = '$kServiceName'" -foregroundcolor Cyan
    Write-Host "  kServiceBinaryPath = '$kServiceBinaryPath'" -foregroundcolor Cyan
    Write-Host "             +exists = $osquerydExists" -foregroundcolor Cyan
    
    Exit 0
  } elseif (($install.ToBool() + $uninstall.ToBool() + $start.ToBool() + $stop.ToBool() + $install_wel_manifest.ToBool() + $uninstall_wel_manifest.ToBool()) -Eq 1) {
    # The above is a dirty method of determining if only one of the following booleans are true.
    Do-Service
  } else {
    Write-Host "Invalid option selected: please see -help for usage details." -foregroundcolor Red
    Exit -1
  }
}

$null = Main
