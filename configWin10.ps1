$funcoes = @(
  ### Requerer acessos administrativos
  "RequireAdmin",
  ### Criar ponto de restauro
  "CriarRestorePoint",
  ### Inntalar Programas adicionais
  "InstalarProgramas",
  ### Desinstalar Windows Apps
  "DesinstalarWinApps",
  ### Ajustes de Privacidade
  "DesativarTelemetria",
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
  ### Ajustes de Segurança
  "SetUACLow",
  "DesativarSMB1",
  "SetCurrentNetworkPrivate",
  "AtivarFirewall",
  "AtivarDefender",
  "AtivarDefenderCloud",
  ### Ajustes de Serviços
  "DesativarAutorun",
  "DesativarStorageSense",
  "DesativarDefragmentation",
  "AtivarIndexing",
  "DesativarHibernation",
  ### Ajustes de UI
  "AtivarLockScreen",
  "DesativarStickyKeys",
  "MostrarTaskManagerDetails"
  "DefinirFileOperationsDetails",
  "DesativarFileDeleteConfirm",
  "MostrarTaskbarSearchIcon",
  "MostrarTaskView",
  "EsconderTaskbarPeopleIcon",
  "DefinirControlPanelLargeIcons",
  "AtivarNumlock",
  # "DesativarNumlock",
  "AtivarDarkMode",
  ### Ajustes de Explorer UI
  "MostrarKnownExtensions",
  "EsconderHiddenFiles",
  "EsconderSyncNotifications",
  "EsconderRecentShortcuts",
  "DefinirExplorerThisPC",
  "MostrarThisPCOnDesktop",
  "MostrarUserFolderOnDesktop",
  "EsconderAtalhoMusica",
  "EsconderAtalhoVideos",
  "EsconderAtalhoObjetos3D",
  ### Ajustes de Aplicações
  "DesinstalarMsftBloat",
  "DesinstalarThirdPartyBloat",
  "DesativarXboxFeatures",
  "DesativarAdobeFlash",
  "InstalarMediaPlayer",
  "InstalarPDFPrinter",
  "DesinstalarXPSPrinter",
  "RemoverFaxPrinter",
  ### Reiniciar PC
  # "Reiniciar"
)

############################################
# Executar script com acesso administrativos
############################################
Function RequireAdmin {
  If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
    Exit
  }
}

####################################################
# Criar ponto de restauro em caso de algo correr mal
####################################################
Function CriarRestorePoint {
  Write-Output "Criando Ponto de Restauro em caso de algo correr mal..."
  Enable-ComputerRestore -Drive "C:\"
  Checkpoint-Computer -Description "PontoRestauro1" -RestorePointType "MODIFY_SETTINGS"
}

#########################
# Instalar programas base
#########################
Function Mostrar-Menu-Choco {
  param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Title,
    
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ChocoInstall
  )
  
  Do {
    Clear-Host
    Write-Host "================ $Title ================"
    Write-Host "S: Pressione 'S' para instalar."
    Write-Host "N: Pressione 'N' para nao instalar."
    Write-Host "Q: Pressione 'Q' para para todo o script."
    $selection = Read-Host "Escolha uma opcao"
    switch ($selection) {
      'y' { choco install $ChocoInstall -y }
      'n' { Break }
      'q' { Exit }
    }
  } Until ($selection -match "y" -or $selection -match "n" -or $selection -match "q")
}

Function InstalarProgramas {
  Write-Output "Instalando Chocolatey"
  Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
  choco install chocolatey-core.extension -y
  Mostrar-Menu-Choco -Title "Quer instalar o Adobe Acrobat Reader?" -ChocoInstall "adobereader"
  Mostrar-Menu-Choco -Title "Quer instalar o 7-Zip?" -ChocoInstall "7zip"
  Mostrar-Menu-Choco -Title "Quer instalar o WinRAR?" -ChocoInstall "winrar"
  Mostrar-Menu-Choco -Title "Quer instalar o VLC?" -ChocoInstall "vlc"
  Mostrar-Menu-Choco -Title "Quer instalar o Irfanview?" -ChocoInstall "irfanview"
  Mostrar-Menu-Choco -Title "Quer instalar o Google Chrome?" -ChocoInstall "googlechrome"
  Mostrar-Menu-Choco -Title "Quer instalar o Firefox?" -ChocoInstall "firefox"
  Mostrar-Menu-Choco -Title "Quer instalar o Notepad++?" -ChocoInstall "notepadplusplus"
  Mostrar-Menu-Choco -Title "Quer instalar o Java Runtime?" -ChocoInstall "javaruntime"
  Mostrar-Menu-Choco -Title "Quer instalar o Office 365 Pro Plus?" -ChocoInstall "office365proplus"
  Clear-Host
}

#######################################
# Desinstalar Aplicações desnecessárias
#######################################
Function DesinstalarWinApps {
  $RemoveApps = @(
    # Windows 10 AppX Apps desnecessárias
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

########################
# Ajustes de Privacidade
########################
# Desativar Telemetria
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

# Dasativar Sensor Wi-Fi
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

# Desativar Web Search no Start Menu
Function DesativarWebSearch {
  Write-Output "Desativando Bing Search no Start Menu..."
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
}

# Desativar Aplicação sugestões e atualizações automáticas
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

# Desativar acesso de aplicações em background
Function DesativarBackgroundApps {
  Write-Output "Desativando acesso de aplicacoes em background..."
  Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Cortana*" | ForEach {
    Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1
    Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1
  }
}

# Desativar Location Tracking
Function DesativarLocationTracking {
  Write-Output "Desativando Location Tracking..."
  If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
}

# Desativar automatic Maps updates
Function DesativarMapUpdates {
  Write-Output "Desativando automatic Maps updates..."
  Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
}

# Desativar Feedback
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

# Desativar Tailored Experiences
Function DesativarTailoredExperiences {
  Write-Output "Desativando Tailored Experiences..."
  If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
    New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
}

# Desativar Advertising ID
Function DesativarAdvertisingID {
  Write-Output "Desativando Advertising ID..."
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
}

# Desativar Cortana
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

# Desativar Error reporting
Function DesativarErrorReporting {
  Write-Output "Desativando Error reporting..."
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
}

# Parar e desativar serviço de Diagnostics Tracking
Function DesativarDiagTrack {
  Write-Output "Parando e desativando servico de Diagnostics Tracking..."
  Stop-Service "DiagTrack" -WarningAction SilentlyContinue
  Set-Service "DiagTrack" -StartupType Disabled
}

######################
# Ajustes de Segurança
######################

# Baixando nivel de UAC
Function SetUACLow {
  Write-Output "Baixando nivel de UAC..."
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0
}

# Desativar protocolo obsoleto SMB 1.0
Function DesativarSMB1 {
  Write-Output "Desativando SMB 1.0 protocol..."
  Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
}

# Mudar perfil da rede atual para privada
Function SetCurrentNetworkPrivate {
  Write-Output "Mudando perfil da rede atual para privada..."
  Set-NetConnectionProfile -NetworkCategory Private
}

# Ativar Firewall
Function AtivarFirewall {
  Write-Output "Ativando Firewall..."
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -ErrorAction SilentlyContinue
}

# Ativar Windows Defender
Function AtivarDefender {
  Write-Output "Ativando Windows Defender..."
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
  If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -Type ExpandString -Value "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`""
  }
  ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063) {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Type ExpandString -Value "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`""
  }
}

# Ativar Windows Defender Cloud
Function AtivarDefenderCloud {
  Write-Output "Ativando Windows Defender Cloud..."
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -ErrorAction SilentlyContinue
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -ErrorAction SilentlyContinue
}

#####################
# Ajustes de Serviços
#####################

# Desativar Autorun para todos os drives
Function DesativarAutorun {
  Write-Output "Desativando Autorun para todos os drives..."
  If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255
}

# Desativar Sensor de armazenamento
Function DesativarStorageSense {
  Write-Output "Desativando Sensor de armazenamento..."
  Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue
}

# Desativar tarefa de desfragmentação
Function DesativarDefragmentation {
  Write-Output "Desativando tarefa de desfragmentacao..."
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
}

# Iniciar e ativar serviço de indexação do Windows Search
Function AtivarIndexing {
  Write-Output "Iniciando e ativando o servico de indexacao do Windows Search..."
  Set-Service "WSearch" -StartupType Automatic
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch" -Name "DelayedAutoStart" -Type DWord -Value 1
  Start-Service "WSearch" -WarningAction SilentlyContinue
}

# Desativar Hibernação
Function DesativarHibernation {
  Write-Output "Desativando Hibernacao..."
  Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 0
  If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0
}

###############
# Ajustes de UI
###############

# Ativar Lock screen
Function AtivarLockScreen {
  Write-Output "Ativando Lock screen..."
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -ErrorAction SilentlyContinue
}

# Desativar mensagem de teclas presas
Function DesativarStickyKeys {
  Write-Output "Desativando mensagem de teclas presas..."
  Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"
}

# Mostrar detalhes no gestor de tarefas
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

# Definir a listagem de ficheiros para detalhes
Function DefinirFileOperationsDetails {
  Write-Output "Definindo a listagem de ficheiros para detalhes..."
  If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
  }
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
}

# Desativar caixa de confirmação para eliminar ficheiros
Function DesativarFileDeleteConfirm {
  Write-Output "Desativando caixa de confirmacao para eliminar ficheiros..."
  Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -ErrorAction SilentlyContinue
}

# Mostrar icon de pesquisa na barra de tarefas
Function MostrarTaskbarSearchIcon {
  Write-Output "Mostrando icon de pesquisa na barra de tarefas..."
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 1
}

# Mostrar icon de vista de taredas
Function MostrarTaskView {
  Write-Output "Mostrando icon de vista de taredas..."
  Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -ErrorAction SilentlyContinue
}

# Esconder icon de pessoas na barra de tarefas
Function EsconderTaskbarPeopleIcon {
  Write-Output "Escondendo icon de pessoas na barra de tarefas..."
  If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
  }
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
}

# Definir vista do Painel de Controlo para icons grandes
Function DefinirControlPanelLargeIcons {
  Write-Output "Definindo vista do Painel de Controlo para icons grandes..."
  If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel")) {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" | Out-Null
  }
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 0
}

# Ativar NumLock depois do arranque
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

# Desativar NumLock depois do arranque
Function DesativarNumlock {
  Write-Output "Desativando NumLock depois do arranque..."
  If (!(Test-Path "HKU:")) {
    New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
  }
  Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483648
  Add-Type -AssemblyName System.Windows.Forms
  If ([System.Windows.Forms.Control]::IsKeyLocked('NumLock')) {
    $wsh = New-Object -ComObject WScript.Shell
    $wsh.SendKeys('{NUMLOCK}')
  }
}

# Ativar Modo Escuro
Function AtivarDarkMode {
  Write-Output "Ativando Modo Escuro"
  Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Value 0
}

########################
# Ajustes de UI Explorer
########################

# Mostrar extensões de ficheiros conhecidos
Function MostrarKnownExtensions {
  Write-Output "Mostrando extensoes de ficheiros conhecidos..."
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
}

# Esconder ficheiros ocultos
Function EsconderHiddenFiles {
  Write-Output "Esconder ficheiros ocultos..."
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 2
}

# Esconder notificações de sincronização
Function EsconderSyncNotifications {
  Write-Output "Escondendo notificacoes de sincronizacao..."
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 0
}

# Esconder atalho para ficheiros frequentes no Explorer
Function EsconderRecentShortcuts {
  Write-Output "Escondendo atalho para ficheiros frequentes no Explorer..."
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type DWord -Value 0
}

# Definir a abertura do Explorer para Este PC
Function DefinirExplorerThisPC {
  Write-Output "Definindo a abertura do Explorer para Este PC..."
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
}

# Mostrar atalho Este PC no Desktop
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

# Mostrar atalho HomeUserFolder no Desktop
Function MostrarUserFolderOnDesktop {
  Write-Output "Mostrando atalho HomeUserFolder no Desktop..."
  If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0
  If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0
}

# Esconder icon Música de Este PC e barra de acesso do Explorer
Function EsconderAtalhoMusica {
  Write-Output "Escondendo icon Musica de Este PC e barra de acesso do Explorer..."
  Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Recurse -ErrorAction SilentlyContinue
  Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -Recurse -ErrorAction SilentlyContinue
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
}

# Esconder icon Vídeos de Este PC e barra de acesso do Explorer
Function EsconderAtalhoVideos {
  Write-Output "Escondendo icon Videos de Este PC e barra de acesso do Explorer..."
  Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Recurse -ErrorAction SilentlyContinue
  Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -Recurse -ErrorAction SilentlyContinue
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
}

# Esconder icon Objetos 3D de Este PC e barra de acesso do Explorer
Function EsconderAtalhoObjetos3D {
  Write-Output "Escondendo icon Objetos 3D de Este PC e barra de acesso do Explorer..."
  Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
  If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
  If (!(Test-Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
    New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
}

#######################
# Ajustes de Aplicações
#######################

# Desinstalar Aplicações Microsoft desnecessárias
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

# Desinstalar Outras aplicações desnecessárias instaladas por defeito
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

# Desativar utilitários Xbox
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

# Desativar Adobe Flash no IE e Edge
Function DesativarAdobeFlash {
  Write-Output "Desativando Adobe Flash no IE e Edge..."
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Name "DisableFlashInIE" -Type DWord -Value 1
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -Type DWord -Value 0
}

# Instalar Windows Media Player
Function InstalarMediaPlayer {
  Write-Output "Instalando Windows Media Player..."
  Enable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Instalar Microsoft Print to PDF
Function InstalarPDFPrinter {
  Write-Output "Instalando Microsoft Print to PDF..."
  Enable-WindowsOptionalFeature -Online -FeatureName "Printing-PrintToPDFServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Desinstalar Microsoft XPS Document Writer
Function DesinstalarXPSPrinter {
  Write-Output "Desinstalando Microsoft XPS Document Writer..."
  Disable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Remover Default Fax Printer
Function RemoverFaxPrinter {
  Write-Output "Removendo Default Fax Printer..."
  Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue
}

# Reiniciar Computador
Function Reiniciar {
  Write-Output "Reiniciando PC..."
  Restart-Computer
}

##########################
# Aplicar todos os ajustes
##########################
$funcoes | ForEach { Invoke-Expression $_ }