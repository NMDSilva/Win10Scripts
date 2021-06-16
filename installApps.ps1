# Localização execução
$disco = 'd'
$path = $disco':\configs'
$printer = "\\172.28.128.26\SafeQ Printer"
$url = "https://gist.githubusercontent.com/NMDSilva/fa95797c747b6ddacb696abc5c43e062/raw/bfea8161559ac96b9fbd3f2954931e0bd821ca5e/settings.json"

# Instalar gestor de pacotes Chocolatey
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Suprimir a necessidade da flag -y em todas as linhas de instalação
choco feature enable -n allowGlobalConfirmation

$wc = New-Object System.Net.WebClient
$wc.DownloadFile($url, "$env:appdata\code\User\settings.json")

# Instalar Fonts
& $path'\Add-Font.ps1' @("$path\apps\fonts")
Add-Printer -ConnectionName $printer # Adicionar Impressora
(New-Object -COM WScript.Network).SetDefaultPrinter($printer) # Pré-definir Impressora

# Definir Pasta de download para disco D:
Import-Module $path\ChangeWinDefaultDownloadPath.psm1
ChangeWinDefaultDownloadPath -DownloadPath $disco':\Downloads'

# Copiar ficheiros para System32
Copy-Item $path\restartpool.ps1 -Destination $env:windir\system32
Copy-Item $path\IPFixo.ps1 -Destination $env:windir\system32
Copy-Item $path\IPAuto.ps1 -Destination $env:windir\system32

# Copiar chaves SSH para .ssh
Copy-Item $path\ssh\* -Destination $env:userprofile\.ssh

# Instalar programas
choco install firacode
choco install putty
choco install curl

# Instalar PHP
choco install php --package-parameters='"/ThreadSafe /InstallDir:'$env:ProgramFiles'\php"'

# Enable the Windows Subsystem for Linux
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart

# Enable Virtual Machine feature
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart

# Download the Linux kernel update package
Invoke-WebRequest -Uri "https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi" -OutFile "$path\apps\wsl_update_x64.msi"
# Install the Linux kernel update package
& $path'\apps\wsl_update_x64.msi' @('/quiet')

refreshenv

# Set WSL 2 as your default version
wsl --set-default-version 2

# Install WinGet
Invoke-WebRequest -Uri "https://github.com/microsoft/winget-cli/releases/download/v1.0.11451/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.appxbundle" -OutFile "$path\apps\WinGet.appxbundle"
Add-AppxPackage "$path\apps\WinGet.appxbundle"

# https://winstall.app/
# Install Apps from WinGet
winget install --id=Microsoft.WindowsTerminal -e
winget install --id=Microsoft.VisualStudioCode -e
winget install --id=VideoLAN.VLC -e
winget install --id=7zip.7zip -e
winget install --id=OpenJS.NodeJS -e
winget install --id=Python.Python.3 -e
winget install --id=SmartBear.SoapUIOpenSource -e
winget install --id=Microsoft.PowerToys -e
winget install --id=Microsoft.PowerShell -e
winget install --id=Microsoft.SQLServerManagementStudio -e
winget install --id=Docker.DockerDesktop -e
winget install --id=AnyDeskSoftwareGmbH.AnyDesk -e
winget install --id=Git.Git -e
winget install --id=Notepad++.Notepad++ -e
winget install --id=Devolutions.RemoteDesktopManager -e
winget install --id=Microsoft.OneDriveInsiders -e
winget install --id=TeamViewer.TeamViewer -e
winget install --id=Insomnia.Insomnia -e
winget install --id=DBBrowserForSQLite.DBBrowserForSQLite -e
winget install --id=Spotify.Spotify -e
winget install --id=WinSCP.WinSCP -e
winget install --id=TimKosse.FileZillaClient -e
winget install --id=GIMP.GIMP -e
winget install --id=QL-Win.QuickLook -e
winget install --id=Canonical.Ubuntu -e
winget install --id=Implbits.HashTab -e
winget install --id=Oracle.JavaRuntimeEnvironment -e

# Enable SandBox Windows
Enable-WindowsOptionalFeature -FeatureName "Containers-DisposableClientVM" -All -Online

# Instalar outros programas
& $path'\apps\ApexSQLRefactor.exe' @('/verysilent', '/norestart')
& $path'\apps\ApexSQLTriggerViewer.exe' @('/verysilent', '/norestart')
& $path'\apps\boonzi-setup.exe'
& $path'\apps\SQL_Tools_Setup_x64.exe'

# Install RSAT
Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online

refreshenv
# Configurar Username GIT
git config --global user.name "Nuno Silva"
# Configurar Email GIT
git config --global user.email "Nuno.D.Silva@seg-social.pt"

npm install -g yo generator-code
npm install -g vsce
