$funcoes = @(
    "ConfiguracoesBase",
    "DesinstalarWinApps",
    "DesativarTelemetria"
    "DesativarSensorWiFi",
    "DesativarWebSearch",
    "DesativarAppSuggestions",
    "DesativarBackgroundApps",
    "DesativarLocationTracking",
    "DesativarMapUpdates",
    "DesativarFeedback",
    "DesativarTailoredExperiences",
    "DesativarAdvertisingID",
    "DesativarCortana",
    "DesativarErrorReporting",
    "DesativarDiagTrack",
    "DesativarStorageSense",
    "DesativarDefragmentation",
    "AtivarIndexing",
    "DesativarStickyKeys",
    "MostrarTaskManagerDetails",
    "DefinirFileOperationsDetails",
    "AtivarNumlock",
    "MostrarTaskManagerDetails",
    "MostrarKnownExtensions",
    "EsconderHiddenFiles",
    "MostrarThisPCOnDesktop",
    "DesinstalarMsftBloat",
    "DesinstalarThirdPartyBloat",
    "DesativarXboxFeatures",
    "InstalarMediaPlayer",
    "InstalarPDFPrinter",
    "DesinstalarXPSPrinter",
    "RemoverFaxPrinter"
)

Function ConfiguracoesBase {

    $path = "d:\configs"
    $printer = "\\172.28.128.28\SafeQ Printer"
    $url = "https://gist.githubusercontent.com/NMDSilva/fa95797c747b6ddacb696abc5c43e062/raw/bfea8161559ac96b9fbd3f2954931e0bd821ca5e/settings.json"

    # Instalar gestor de pacotes Chocolatey
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

    # Suprimir a necessidade da flag -y em todas as linhas de instalaÃ§Ã£o
    choco feature enable -n allowGlobalConfirmation

    (New-Object System.Net.WebClient).DownloadFile($url, "$env:appdata\code\User\settings.json")

    # Instalar Fonts
    & $path'\Add-Font.ps1' @("$path\apps\fonts")
    Add-Printer -ConnectionName $printer # Adicionar Impressora
    (New-Object -COM WScript.Network).SetDefaultPrinter($printer) # PrÃ©-definir Impressora

    # Definir Pasta de download para disco D:
    Import-Module $path\ChangeWinDefaultDownloadPath.psm1
    ChangeWinDefaultDownloadPath -DownloadPath $disco':\Downloads'

    # Copiar ficheiros para System32
    Copy-Item $path\restartpool.ps1 -Destination $env:windir\system32
    Copy-Item $path\IPFixo.ps1 -Destination $env:windir\system32
    Copy-Item $path\IPAuto.ps1 -Destination $env:windir\system32

    # Copiar chaves SSH para .ssh
    New-Item -Path $env:userprofile\.ssh -ItemType Directory
    Copy-Item $path\ssh\* -Destination $env:userprofile\.ssh

    # Instalar programas
    choco install firacode
    choco install curl

    # Instalar PHP
    choco install php --package-parameters='"/ThreadSafe /InstallDir:'$env:ProgramFiles'\php"'

    # Enable the Windows Subsystem for Linux
    dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart

    # Set WSL 2 as your default version
    wsl --set-default-version 2

    # https://winstall.app/
    # Install Apps from WinGet
    winget install -e --id=Microsoft.WindowsTerminal
    winget install -e --id=Microsoft.VisualStudioCode
    winget install -e --id=VideoLAN.VLC
    winget install -e --id=7zip.7zip
    winget install -e --id=OpenJS.NodeJS
    winget install -e --id=Python.Python.3
    winget install -e --id=SmartBear.SoapUIOpenSource
    winget install -e --id=Microsoft.PowerToys
    winget install -e --id=Microsoft.PowerShell
    winget install -e --id=Microsoft.SQLServerManagementStudio
    winget install -e --id=Docker.DockerDesktop
    winget install -e --id=AnyDeskSoftwareGmbH.AnyDesk
    winget install -e --id=Git.Git -v 2.32.0
    winget install -e --id=Devolutions.RemoteDesktopManager
    winget install -e --id=TeamViewer.TeamViewer
    winget install -e --id=Insomnia.Insomnia
    winget install -e --id=WinSCP.WinSCP
    winget install -e --id=TimKosse.FileZillaClient

    # Instalar outros programas
    & $path'\apps\ApexSQLRefactor.exe' @('/verysilent', '/norestart')
    & $path'\apps\ApexSQLTriggerViewer.exe' @('/verysilent', '/norestart')
    & $path'\apps\boonzi-setup.exe'
    & $path'\apps\SQL_Tools_Setup_x64.exe'

    refreshenv
    # Configurar Username GIT
    git config --global user.name "Nuno Silva"
    # Configurar Email GIT
    git config --global user.email "Nuno.D.Silva@seg-social.pt"

    npm install -g yo generator-code
    npm install -g vsce

    Write-Host "Instalação concluída" -ForegroundColor green
}

Function DesinstalarWinApps {
  $RemoveApps = @(
    # Windows 10 AppX Apps desnecessÃ¡rias
    "Microsoft.BingNews"
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.Messaging"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.NetworkSpeedTest"
    "Microsoft.News"
    "Microsoft.Office.Lens"
    "Microsoft.Office.Sway"
    "Microsoft.OneConnect"
    "Microsoft.People"
    "Microsoft.Print3D"
    "Microsoft.SkypeApp"
    "Microsoft.StorePurchaseApp"
    "Microsoft.Whiteboard"
    "Microsoft.WindowsAlarms"
    "microsoft.windowscommunicationsapps"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.WindowsMaps"
    "Microsoft.WindowsSoundRecorder"
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"
    # Windows 10 AppX Apps Publicidades
    "*EclipseManager*"
    "*ActiproSoftwareLLC*"
    "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
    "*Duolingo-LearnLanguagesforFree*"
    "*PandoraMediaInc*"
    "*CandyCrush*"
    "*BubbleWitch3Saga*"
    "*Wunderlist*"
    "*Flipboard*"
    "*Twitter*"
    "*Facebook*"
    "*Spotify*"
    "*Royal Revolt*"
    "*Sway*"
    "*Speed Test*"
    "*Dolby*"
  )
  foreach ($App in $RemoveApps) {
    Get-AppxPackage -Name $App | Remove-AppxPackage
    Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $App | Remove-AppxProvisionedPackage -Online
    Write-Output "Tentando remover $App."
  }
}

Function DesativarTelemetria {
  Write-Output "Desativando Telemetria..."
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
  Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
}

Function DesativarSensorWiFi {
  Write-Output "Desativando Sensor Wi-Fi..."
  If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
  If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Type Dword -Value 0
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Type Dword -Value 0
}

Function DesativarWebSearch {
  Write-Output "Desativando Bing Search no Start Menu..."
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
}

Function DesativarAppSuggestions {
  Write-Output "Desativando Aplicacao Sugestoes..."
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
}

Function DesativarBackgroundApps {
  Write-Output "Desativando acesso de aplicacoes em background..."
  Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Cortana*" | ForEach {
    Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1
    Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1
  }
}

Function DesativarLocationTracking {
  Write-Output "Desativando Location Tracking..."
  If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
}

Function DesativarMapUpdates {
  Write-Output "Desativando automatic Maps updates..."
  Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
}

Function DesativarFeedback {
  Write-Output "Desativando Feedback..."
  If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
}

Function DesativarTailoredExperiences {
  Write-Output "Desativando Tailored Experiences..."
  If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
    New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
}

Function DesativarAdvertisingID {
  Write-Output "Desativando Advertising ID..."
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
}

Function DesativarCortana {
  Write-Output "Desativando Cortana..."
  If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
  If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
  If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
}

Function DesativarErrorReporting {
  Write-Output "Desativando Error reporting..."
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
}

Function DesativarDiagTrack {
  Write-Output "Parando e desativando servico de Diagnostics Tracking..."
  Stop-Service "DiagTrack" -WarningAction SilentlyContinue
  Set-Service "DiagTrack" -StartupType Disabled
}

Function DesativarStorageSense {
  Write-Output "Desativando Sensor de armazenamento..."
  Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue
}

Function DesativarDefragmentation {
  Write-Output "Desativando tarefa de desfragmentacao..."
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
}

Function AtivarIndexing {
  Write-Output "Iniciando e ativando o servico de indexacao do Windows Search..."
  Set-Service "WSearch" -StartupType Automatic
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch" -Name "DelayedAutoStart" -Type DWord -Value 1
  Start-Service "WSearch" -WarningAction SilentlyContinue
}

Function DesativarStickyKeys {
  Write-Output "Desativando mensagem de teclas presas..."
  Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"
}

Function MostrarTaskManagerDetails {
  Write-Output "Mostrando detalhes no gestor de tarefas..."
  $taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
  Do {
    Start-Sleep -Milliseconds 100
    $preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
  } Until ($preferences)
  Stop-Process $taskmgr
  $preferences.Preferences[28] = 0
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
}

Function DefinirFileOperationsDetails {
  Write-Output "Definindo a listagem de ficheiros para detalhes..."
  If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
  }
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
}

Function AtivarNumlock {
  Write-Output "Ativando NumLock depois do arranque..."
  If (!(Test-Path "HKU:")) {
    New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
  }
  Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
  Add-Type -AssemblyName System.Windows.Forms
  If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
    $wsh = New-Object -ComObject WScript.Shell
    $wsh.SendKeys('{NUMLOCK}')
  }
}

Function MostrarKnownExtensions {
  Write-Output "Mostrando extensoes de ficheiros conhecidos..."
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
}

Function EsconderHiddenFiles {
  Write-Output "Esconder ficheiros ocultos..."
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 2
}

Function MostrarThisPCOnDesktop {
  Write-Output "Mostrando atado Este PC no Desktop..."
  If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
  If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
}

Function DesinstalarMsftBloat {
  Write-Output "Desinstalando Aplicacoes Microsoft desnecessarias..."
  Get-AppxPackage "Microsoft.3DBuilder" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.AppConnector" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.BingTranslator" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.CommsPhone" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.ConnectivityStore" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.GetHelp" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.Messaging" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.Microsoft3DViewer" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.MicrosoftPowerBIForWindows" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.MicrosoftStickyNotes" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.NetworkSpeedTest" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.Office.OneNote" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.Office.Sway" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.OneConnect" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.People" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.Print3D" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.Wallet" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.WindowsAlarms" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.WindowsCamera" | Remove-AppxPackage
  Get-AppxPackage "microsoft.windowscommunicationsapps" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.WindowsMaps" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.WindowsPhone" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.ZuneMusic" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.ZuneVideo" | Remove-AppxPackage
}

Function DesinstalarThirdPartyBloat {
  Write-Output "Desinstalando outras aplicacoes desnecessarias instaladas por defeito..."
  Get-AppxPackage "2414FC7A.Viber" | Remove-AppxPackage
  Get-AppxPackage "41038Axilesoft.ACGMediaPlayer" | Remove-AppxPackage
  Get-AppxPackage "46928bounde.EclipseManager" | Remove-AppxPackage
  Get-AppxPackage "4DF9E0F8.Netflix" | Remove-AppxPackage
  Get-AppxPackage "64885BlueEdge.OneCalendar" | Remove-AppxPackage
  Get-AppxPackage "7EE7776C.LinkedInforWindows" | Remove-AppxPackage
  Get-AppxPackage "828B5831.HiddenCityMysteryofShadows" | Remove-AppxPackage
  Get-AppxPackage "89006A2E.AutodeskSketchBook" | Remove-AppxPackage
  Get-AppxPackage "9E2F88E3.Twitter" | Remove-AppxPackage
  Get-AppxPackage "A278AB0D.DisneyMagicKingdoms" | Remove-AppxPackage
  Get-AppxPackage "A278AB0D.MarchofEmpires" | Remove-AppxPackage
  Get-AppxPackage "ActiproSoftwareLLC.562882FEEB491" | Remove-AppxPackage
  Get-AppxPackage "AdobeSystemsIncorporated.AdobePhotoshopExpress" | Remove-AppxPackage
  Get-AppxPackage "CAF9E577.Plex" | Remove-AppxPackage
  Get-AppxPackage "D52A8D61.FarmVille2CountryEscape" | Remove-AppxPackage
  Get-AppxPackage "D5EA27B7.Duolingo-LearnLanguagesforFree" | Remove-AppxPackage
  Get-AppxPackage "DB6EA5DB.CyberLinkMediaSuiteEssentials" | Remove-AppxPackage
  Get-AppxPackage "DolbyLaboratories.DolbyAccess" | Remove-AppxPackage
  Get-AppxPackage "Drawboard.DrawboardPDF" | Remove-AppxPackage
  Get-AppxPackage "Facebook.Facebook" | Remove-AppxPackage
  Get-AppxPackage "flaregamesGmbH.RoyalRevolt2" | Remove-AppxPackage
  Get-AppxPackage "GAMELOFTSA.Asphalt8Airborne" | Remove-AppxPackage
  Get-AppxPackage "KeeperSecurityInc.Keeper" | Remove-AppxPackage
  Get-AppxPackage "king.com.BubbleWitch3Saga" | Remove-AppxPackage
  Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage
  Get-AppxPackage "PandoraMediaInc.29680B314EFC2" | Remove-AppxPackage
  Get-AppxPackage "SpotifyAB.SpotifyMusic" | Remove-AppxPackage
  Get-AppxPackage "WinZipComputing.WinZipUniversal" | Remove-AppxPackage
  Get-AppxPackage "XINGAG.XING" | Remove-AppxPackage
}

Function DesativarXboxFeatures {
  Write-Output "Desativando utilitarios Xbox..."
  Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage -ErrorAction SilentlyContinue
  Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
  Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage
  Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0
}

Function InstalarMediaPlayer {
  Write-Output "Instalando Windows Media Player..."
  Enable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

Function InstalarPDFPrinter {
  Write-Output "Instalando Microsoft Print to PDF..."
  Enable-WindowsOptionalFeature -Online -FeatureName "Printing-PrintToPDFServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

Function DesinstalarXPSPrinter {
  Write-Output "Desinstalando Microsoft XPS Document Writer..."
  Disable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

Function RemoverFaxPrinter {
  Write-Output "Removendo Default Fax Printer..."
  Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue
}

$funcoes | ForEach { Invoke-Expression $_ }
