# Installing osquery on Windows

We recommend installing on Windows using the [Chocolatey package manager](https://chocolatey.org/packages/osquery/), or from the latest official binaries available on [the Downloads page](https://osquery.io/downloads/official/).

For those needing more customization of their deployment, the steps taken by the installation are explained in more detail, below.

## Installing with Chocolatey

Each osquery tag (stable release) is published to **Chocolatey** for our supported versions: [https://chocolatey.org/packages/osquery/](https://chocolatey.org/packages/osquery/)

By default Chocolatey will install the binaries, example packs, example configuration, and an OpenSSL certificate bundle to `C:\Program Files\osquery` and nothing more. You can pass Chocolatey the `--params='/InstallService'` flag or make use of osquery's `--install` flag with `C:\Program Files\osquery\osqueryd\osqueryd.exe --install` to install a Windows `SYSTEM`-level service for the `osqueryd` daemon.

## Installing osquery via the MSI package

For generating an **MSI** installer package, we support two methods.

The first method is with minor modifications to the CMake build steps:

1. First, install the Wix Toolset. With Chocolatey, `choco install wixtoolset` and then add `C:\Program Files (x86)\WiX Toolset v3.11\bin` to the system PATH. As of the time of this writing, the Chocolatey package installer doesn't add this to the PATH for you; you must add it yourself.
2. When configuring the build, specify a version string for the osquery package using the CMake parameter `-DOSQUERY_VERSION`.
3. When building, provide an additional CMake parameter, `--target package`.

An example of a CMake build that generates an MSI package:

```PowerShell
cd \projects\osquery\build
cmake -G "Visual Studio 16 2019" -A x64 -T v141 -DOSQUERY_VERSION="4.0.0" ..\src
cmake --build . --config RelWithDebInfo --target package
```

The second method is to use the script `make_windows_package.ps1` included in the source tree. This is a PowerShell script that will generate an MSI package for installing osquery. Running `.\tools\deployment\make_windows_package.ps1 'msi'` from the source root will generate a standalone MSI package along with the example packs, configuration, and OpenSSL cert bundle.

## Installing Manually

To get osquery running as a `SYSTEM`-level service on Windows, one must ensure two things:

1. `osqueryd.exe` is running with safe permissions
2. The Windows Service Control Manager has all of the correct information for running the daemon

The `osqueryd.exe` daemon is considered safe if the binary and the directory in which the binary resides do not allow non-privileged write accesses and both are owned by either the Administrators group or the `SYSTEM` account.

The recommended way to set these ACLs is with PowerShell, and we've written a helper function to handle these permissions. To do so, `.` source the file and call the function, as follows:

```PowerShell
C:\Users\Thor\work\repos\osquery [master ≡]
λ  . .\tools\deployment\chocolatey\tools\osquery_utils.ps1
C:\Users\Thor\work\repos\osquery [master ≡]
λ  Set-SafePermissions C:\Program Files\osquery\osqueryd\
True
```

If you'd prefer to manually set the permissions, check the `C:\Program Files\osquery\osqueryd` directory and ensure that no users or groups have write permissions with the exception of the Administrators group or the SYSTEM account. Read and execute permissions are expected and safe, so also ensure the Users group has both.

Now that osquery is properly laid out on the filesystem, we need to create a new Windows service to launch and manage the daemon. If you're using Chocolatey, you can pass the `--params='/InstallService'` flag during installation to have Chocolatey set up the Windows service for you. In general, any method to install a Windows system service will suffice. You just need to ensure to specify the `--flagfile` option in the service binary path, and give the full paths for both the daemon binary and flag file.

For example:

* To install the service using Powershell we bundle a helper function living in the repo at `.\tools\manage-osqueryd.ps1` which can be invoked as follows:

````PowerShell
C:\Program Files\osquery
λ  .\manage-osqueryd.ps1 -install -startupArgs "C:\Program Files\osquery\osquery.flags"
````

* If you'd rather use Powershell to manually create the service you can run:

```PowerShell
C:\Users\Thor\work\repos\osquery [master ≡]
λ  New-Service -Name "osqueryd" -BinaryPathName "C:\Program Files\osquery\osqueryd\osqueryd.exe --flagfile=C:\Program Files\osquery\osquery.flags"
```

* Lastly, if you'd prefer to use the Windows service utility `sc.exe` you can use:

```PowerShell
C:\Users\Thor\work\repos\osquery [master ≡]
λ  sc.exe create osqueryd type= own start= auto error= normal binpath= "C:\Program Files\osquery\osqueryd\osqueryd.exe --flagfile=\Program Files\osquery\osquery.flags" displayname= 'osqueryd'
```

## Running osquery

Out of the box via the Chocolatey installation, one can run osquery in the interactive shell mode using `osqueryi`. More commonly, however, the daemon is configured to be a system service. To set this up, you'll need to install the daemon via the service installation flags as detailed in the steps above, and then provide the daemon with a config file. The simplest way to get `osqueryd` up and running is to rename the `C:\Program Files\osquery\osquery.example.conf` file provided to `osquery.conf`. Once the configuration file is in place, you can start the Windows service:

* `Start-Service osqueryd` if you're using **Powershell**
* `sc.exe start osqueryd` if you're using **cmd.exe**

We recommend configuring large fleets with Chef or SCCM.

## Managing the daemon service

osquery provides a helper script for [managing the osquery daemon service](https://github.com/osquery/osquery/blob/master/tools/manage-osqueryd.ps1), which is installed to `C:\Program Files\osquery\manage-osqueryd.ps1`.

## Packaging osquery

If you'd like to create your own osquery Chocolatey package, you can run [`.\tools\deployment\make_windows_package.ps1`](https://github.com/osquery/osquery/blob/master/tools/deployment/make_windows_package.ps1). This script will grab the built binaries, the [`packs`](https://github.com/osquery/osquery/blob/master/packs) directory, the [`osquery.example.conf`](https://github.com/osquery/osquery/blob/master/tools/deployment/osquery.example.conf), and attempt to find the OpenSSL `certs.pem` at `C:\Program Files\chocolatey\lib\openssl\local\certs`.

## Enabling Windows Event Log support

In order to enable support for the Windows Event Log, you first have to install the manifest file. To install and uninstall it manually, you can use the built-in `wevtutil` command:

* **Install**: `wevtutil im C:\Program Files\osquery\osquery.man`
* **Uninstall**: `wevtutil um C:\Program Files\osquery\osquery.man`

The same operation can be performed using the osquery manager (`C:\Program Files\osquery\manage-osqueryd.ps1`):

* **Install**: `.\manage-osqueryd.ps1 -installWelManifest`
* **Uninstall**: `.\manage-osqueryd.ps1 -uninstallWelManifest`

The manifest file path can also be overridden using the `-welManifestPath` switch.

To verify that everything has been configured correctly, open the Event Viewer and search for the **osquery** folder under `Applications and Services Logs/osquery/osquery`.

To instruct osquery to use the channel you just created, change the configuration file to use the **windows_event_log** logger plugin.
