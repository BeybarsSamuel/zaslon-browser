!macro customInstall
  ; Windows Search / Win+R App Paths kaydi (Chrome benzeri tam Windows entegrasyonu)
  WriteRegStr SHELL_CONTEXT "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Zaslon Browser.exe" "" "$INSTDIR\Zaslon Browser.exe"
  WriteRegStr SHELL_CONTEXT "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Zaslon Browser.exe" "Path" "$INSTDIR"

  ; Windows Tarayici Kaydi (Varsayilan Uygulamalar & Arama listesi)
  WriteRegStr SHELL_CONTEXT "SOFTWARE\Clients\StartMenuInternet\Zaslon Browser" "" "Zaslon Browser"
  WriteRegStr SHELL_CONTEXT "SOFTWARE\Clients\StartMenuInternet\Zaslon Browser\DefaultIcon" "" "$INSTDIR\Zaslon Browser.exe,0"
  WriteRegStr SHELL_CONTEXT "SOFTWARE\Clients\StartMenuInternet\Zaslon Browser\shell\open\command" "" '"$INSTDIR\Zaslon Browser.exe"'
  WriteRegStr SHELL_CONTEXT "SOFTWARE\Clients\StartMenuInternet\Zaslon Browser\Capabilities" "ApplicationName" "Zaslon Browser"
  WriteRegStr SHELL_CONTEXT "SOFTWARE\Clients\StartMenuInternet\Zaslon Browser\Capabilities" "ApplicationDescription" "Zaslon Browser - Gizlilik ve Güvenlik Odaklı Tarayıcı"
  WriteRegStr SHELL_CONTEXT "SOFTWARE\Clients\StartMenuInternet\Zaslon Browser\Capabilities" "ApplicationIcon" "$INSTDIR\Zaslon Browser.exe,0"
  WriteRegStr SHELL_CONTEXT "SOFTWARE\Clients\StartMenuInternet\Zaslon Browser\Capabilities\URLAssociations" "http" "ZaslonHTML"
  WriteRegStr SHELL_CONTEXT "SOFTWARE\Clients\StartMenuInternet\Zaslon Browser\Capabilities\URLAssociations" "https" "ZaslonHTML"
  WriteRegStr SHELL_CONTEXT "SOFTWARE\RegisteredApplications" "Zaslon Browser" "SOFTWARE\Clients\StartMenuInternet\Zaslon Browser\Capabilities"
  WriteRegStr SHELL_CONTEXT "SOFTWARE\Classes\ZaslonHTML" "" "Zaslon Browser Web Document"
  WriteRegStr SHELL_CONTEXT "SOFTWARE\Classes\ZaslonHTML\DefaultIcon" "" "$INSTDIR\Zaslon Browser.exe,0"
  WriteRegStr SHELL_CONTEXT "SOFTWARE\Classes\ZaslonHTML\shell\open\command" "" '"$INSTDIR\Zaslon Browser.exe" "%1"'
!macroend

!macro customUnInstall
  DeleteRegKey SHELL_CONTEXT "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Zaslon Browser.exe"
  DeleteRegKey SHELL_CONTEXT "SOFTWARE\Clients\StartMenuInternet\Zaslon Browser"
  DeleteRegValue SHELL_CONTEXT "SOFTWARE\RegisteredApplications" "Zaslon Browser"
  DeleteRegKey SHELL_CONTEXT "SOFTWARE\Classes\ZaslonHTML"
!macroend
