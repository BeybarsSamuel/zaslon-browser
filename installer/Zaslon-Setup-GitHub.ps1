<#
.SYNOPSIS
  Zaslon Browser — GitHub Bootstrapper / Setup Installer
  Public veya Private GitHub deposundan en son Zaslon Browser surumunu cekip
  bilgisayardaki Program Files (veya secilen) dizinine kurar, Masaustu + Baslat
  Menusu kisayollarini ve Windows Arama/App Paths kayitlarini Chrome gibi ekler.
#>

[CmdletBinding()]
param(
    [string]$Repo = "",
    [string]$Token = "",
    [string]$InstallDir = "$env:ProgramFiles\Zaslon Browser"
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

function Normalize-GitHubRepo([string]$raw) {
    $s = ($raw -as [string]).Trim()
    if ([string]::IsNullOrWhiteSpace($s)) { return "" }
    $s = $s -replace '^https?://(www\.)?github\.com/', ''
    $s = $s -replace '\.git$', ''
    $s = $s.Trim('/')
    $parts = $s.Split('/') | Where-Object { $_ -ne '' }
    if ($parts.Count -eq 1) {
        return "$($parts[0])/zaslon-browser"
    }
    if ($parts.Count -ge 2) {
        return "$($parts[0])/$($parts[1])"
    }
    return ""
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-Shortcut([string]$ShortcutPath, [string]$TargetPath, [string]$WorkingDir, [string]$Description) {
    $shell = New-Object -ComObject WScript.Shell
    $sc = $shell.CreateShortcut($ShortcutPath)
    $sc.TargetPath = $TargetPath
    $sc.WorkingDirectory = $WorkingDir
    $sc.IconLocation = "$TargetPath,0"
    $sc.Description = $Description
    $sc.Save()
}

function Register-WindowsApp([string]$ExePath, [string]$DirPath, [string]$VersionStr, [bool]$MachineWide) {
    $hive = if ($MachineWide) { "HKLM:" } else { "HKCU:" }

    # 1. Windows Search ve Win+R icin App Paths
    $appPathsKey = "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Zaslon Browser.exe"
    New-Item -Path $appPathsKey -Force | Out-Null
    Set-ItemProperty -Path $appPathsKey -Name "(Default)" -Value $ExePath
    Set-ItemProperty -Path $appPathsKey -Name "Path" -Value $DirPath

    # 2. Windows Tarayici Kaydi (StartMenuInternet & RegisteredApplications)
    $browserRoot = "$hive\SOFTWARE\Clients\StartMenuInternet\Zaslon Browser"
    New-Item -Path "$browserRoot\DefaultIcon" -Force | Out-Null
    New-Item -Path "$browserRoot\shell\open\command" -Force | Out-Null
    New-Item -Path "$browserRoot\Capabilities\URLAssociations" -Force | Out-Null
    Set-ItemProperty -Path $browserRoot -Name "(Default)" -Value "Zaslon Browser"
    Set-ItemProperty -Path "$browserRoot\DefaultIcon" -Name "(Default)" -Value "$ExePath,0"
    Set-ItemProperty -Path "$browserRoot\shell\open\command" -Name "(Default)" -Value "`"$ExePath`""
    Set-ItemProperty -Path "$browserRoot\Capabilities" -Name "ApplicationName" -Value "Zaslon Browser"
    Set-ItemProperty -Path "$browserRoot\Capabilities" -Name "ApplicationDescription" -Value "Zaslon Browser - Gizlilik ve Guvenlik Odakli Tarayici"
    Set-ItemProperty -Path "$browserRoot\Capabilities" -Name "ApplicationIcon" -Value "$ExePath,0"
    Set-ItemProperty -Path "$browserRoot\Capabilities\URLAssociations" -Name "http" -Value "ZaslonHTML"
    Set-ItemProperty -Path "$browserRoot\Capabilities\URLAssociations" -Name "https" -Value "ZaslonHTML"

    $regApps = "$hive\SOFTWARE\RegisteredApplications"
    New-Item -Path $regApps -Force | Out-Null
    Set-ItemProperty -Path $regApps -Name "Zaslon Browser" -Value "SOFTWARE\Clients\StartMenuInternet\Zaslon Browser\Capabilities"

    $progId = "$hive\SOFTWARE\Classes\ZaslonHTML"
    New-Item -Path "$progId\DefaultIcon" -Force | Out-Null
    New-Item -Path "$progId\shell\open\command" -Force | Out-Null
    Set-ItemProperty -Path $progId -Name "(Default)" -Value "Zaslon Browser Web Document"
    Set-ItemProperty -Path "$progId\DefaultIcon" -Name "(Default)" -Value "$ExePath,0"
    Set-ItemProperty -Path "$progId\shell\open\command" -Name "(Default)" -Value "`"$ExePath`" `"%1`""

    # 3. Portable/Zip kurulumlarinda Windows Ayarlar > Yuklu Uygulamalar gorunurlugu (NSIS zaten kendi olusturur)
    $uninstKey = "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\org.zaslon.browser"
    $existingNsisUninst = Get-ChildItem "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue |
                          Where-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DisplayName -eq "Zaslon Browser" }
    if (-not $existingNsisUninst) {
        New-Item -Path $uninstKey -Force | Out-Null
        Set-ItemProperty -Path $uninstKey -Name "DisplayName" -Value "Zaslon Browser"
        Set-ItemProperty -Path $uninstKey -Name "DisplayIcon" -Value "$ExePath,0"
        Set-ItemProperty -Path $uninstKey -Name "DisplayVersion" -Value ($VersionStr -replace '^v', '')
        Set-ItemProperty -Path $uninstKey -Name "Publisher" -Value "Zaslon Privacy Team"
        Set-ItemProperty -Path $uninstKey -Name "InstallLocation" -Value $DirPath
        Set-ItemProperty -Path $uninstKey -Name "UninstallString" -Value "powershell.exe -NoProfile -Command `"Remove-Item -Path '$DirPath' -Recurse -Force`""
        Set-ItemProperty -Path $uninstKey -Name "NoModify" -Value 1 -Type DWord
        Set-ItemProperty -Path $uninstKey -Name "NoRepair" -Value 1 -Type DWord
    }
}

function Refresh-WindowsShell {
    try {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class ZaslonShellNotify {
    [DllImport("shell32.dll")]
    public static extern void SHChangeNotify(int wEventId, int uFlags, IntPtr dwItem1, IntPtr dwItem2);
}
"@ -ErrorAction SilentlyContinue
        [ZaslonShellNotify]::SHChangeNotify(0x08000000, 0, [IntPtr]::Zero, [IntPtr]::Zero)
    } catch {}
}

function Get-GitHubHeaders([string]$Pat, [string]$Accept = "application/vnd.github+json") {
    $h = @{
        "Accept"               = $Accept
        "X-GitHub-Api-Version" = "2022-11-28"
        "User-Agent"           = "Zaslon-Installer"
    }
    if (-not [string]::IsNullOrWhiteSpace($Pat)) {
        $h["Authorization"] = "Bearer $Pat"
    }
    return $h
}

function Parse-Sha256Sums([string]$Text, [string]$FileName) {
    $target = [System.IO.Path]::GetFileName($FileName).ToLowerInvariant()
    foreach ($line in ($Text -split "`r?`n")) {
        $t = $line.Trim()
        if ($t -match '^([a-fA-F0-9]{64})(?:\s+\*?(.+))?$') {
            if (-not $Matches[2]) { return $Matches[1].ToLowerInvariant() }
            $fname = [System.IO.Path]::GetFileName($Matches[2].Trim()).ToLowerInvariant()
            if ($fname -eq $target) { return $Matches[1].ToLowerInvariant() }
        }
    }
    return ""
}

Clear-Host
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "   ZASLON BROWSER - GitHub Kurulum Sihirbazi" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

if ([string]::IsNullOrWhiteSpace($Repo)) {
    $defaultRepo = "BeybarsSamuel/zaslon-browser"
    $rawRepo = Read-Host "GitHub Repo [$defaultRepo]"
    if ([string]::IsNullOrWhiteSpace($rawRepo)) { $rawRepo = $defaultRepo }
    $Repo = Normalize-GitHubRepo $rawRepo
} else {
    $Repo = Normalize-GitHubRepo $Repo
}

if ([string]::IsNullOrWhiteSpace($Repo)) {
    Write-Host "[HATA] Gecerli bir GitHub deposu girilmedi." -ForegroundColor Red
    exit 1
}

if ([string]::IsNullOrWhiteSpace($Token)) {
    $ghToken = ""
    if (Get-Command gh -ErrorAction SilentlyContinue) {
        try {
            $ghToken = (gh auth token 2>$null | Out-String).Trim()
        } catch {}
    }

    if (-not [string]::IsNullOrWhiteSpace($ghToken)) {
        $useGh = Read-Host "GitHub CLI (gh) oturumu bulundu. Private erisim icin kullanilsin mi? (E/h) [E]"
        if ($useGh -eq "" -or $useGh -match '^[EeYy]') {
            $Token = $ghToken
        }
    }

    if ([string]::IsNullOrWhiteSpace($Token)) {
        $secTok = Read-Host "Private repo ise GitHub PAT Token girin (Public ise bos birakip Enter)" -AsSecureString
        if ($secTok -and $secTok.Length -gt 0) {
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secTok)
            try {
                $Token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
            } finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        }
    }
}

$customDir = Read-Host "Kurulum Klasoru [$InstallDir]"
if (-not [string]::IsNullOrWhiteSpace($customDir)) {
    $InstallDir = $customDir.Trim()
}

$needsAdmin = $InstallDir.StartsWith($env:ProgramFiles, [System.StringComparison]::OrdinalIgnoreCase) -or
              (${env:ProgramFiles(x86)} -and $InstallDir.StartsWith(${env:ProgramFiles(x86)}, [System.StringComparison]::OrdinalIgnoreCase))

if ($needsAdmin -and -not (Test-IsAdmin)) {
    Write-Host ""
    Write-Host "[BILGI] '$InstallDir' dizinine kurulum icin Yonetici (UAC) izni isteniyor..." -ForegroundColor Yellow
    $argList = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", "`"$PSCommandPath`"",
        "-Repo", "`"$Repo`"",
        "-InstallDir", "`"$InstallDir`""
    )
    if (-not [string]::IsNullOrWhiteSpace($Token)) {
        $argList += @("-Token", "`"$Token`"")
    }
    $proc = Start-Process -FilePath "powershell.exe" -ArgumentList $argList -Verb RunAs -PassThru -Wait
    exit $proc.ExitCode
}

Write-Host ""
Write-Host "[1/4] GitHub deposu kontrol ediliyor: $Repo ..." -ForegroundColor Gray
$headers = Get-GitHubHeaders -Pat $Token -Accept "application/vnd.github+json"

try {
    $repoInfo = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo" -Headers $headers -Method Get
    $vis = if ($repoInfo.private) { "Private" } else { "Public" }
    Write-Host "      Depo erisimi basarili ($vis)." -ForegroundColor Green
} catch {
    Write-Host "[HATA] GitHub deposuna erisilemedi: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "       Private repo kullaniyorsaniz 'repo' yetkili bir GitHub PAT Token girin." -ForegroundColor Yellow
    exit 1
}

Write-Host "[2/4] En guncel Masaustu Release araniyor..." -ForegroundColor Gray
$releases = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases?per_page=15" -Headers $headers -Method Get
$chosenRel = $null
$chosenAsset = $null

foreach ($rel in $releases) {
    if ($rel.draft -or $rel.prerelease) { continue }
    $assets = @($rel.assets)
    $setup = $assets | Where-Object { $_.name -match '\.exe$' -and $_.name -match 'setup|installer' } | Select-Object -First 1
    $portable = $assets | Where-Object { $_.name -match '\.exe$' -and $_.name -match 'portable' } | Select-Object -First 1
    $anyExe = $assets | Where-Object { $_.name -match '\.exe$' } | Select-Object -First 1
    $zipAsset = $assets | Where-Object { $_.name -match '\.zip$' -and $_.name -match 'win|zaslon|desktop' } | Select-Object -First 1

    if ($setup) { $chosenRel = $rel; $chosenAsset = $setup; break }
    if ($portable) { $chosenRel = $rel; $chosenAsset = $portable; break }
    if ($anyExe) { $chosenRel = $rel; $chosenAsset = $anyExe; break }
    if ($zipAsset) { $chosenRel = $rel; $chosenAsset = $zipAsset; break }
}

if (-not $chosenRel -or -not $chosenAsset) {
    Write-Host "[HATA] GitHub Releases icinde indirilebilir Windows kurulum dosyasi (.exe/.zip) bulunamadi." -ForegroundColor Red
    exit 1
}

Write-Host "      Bulunan surum: $($chosenRel.tag_name) -> $($chosenAsset.name)" -ForegroundColor Green

$tempDir = Join-Path $env:TEMP ("zaslon-gh-setup-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

try {
    $dlHeaders = Get-GitHubHeaders -Pat $Token -Accept "application/octet-stream"
    $assetOut = Join-Path $tempDir $chosenAsset.name
    $assetUrl = if ($chosenAsset.url) { $chosenAsset.url } else { $chosenAsset.browser_download_url }

    Write-Host "[3/4] Indiriliyor ($($chosenAsset.name))..." -ForegroundColor Gray
    Invoke-WebRequest -Uri $assetUrl -Headers $dlHeaders -OutFile $assetOut

    $sumAsset = @($chosenRel.assets) | Where-Object {
        $_.name -ieq "$($chosenAsset.name).sha256" -or $_.name -imatch '^sha2-?256sums(\.txt)?$'
    } | Select-Object -First 1

    if ($sumAsset) {
        $sumUrl = if ($sumAsset.url) { $sumAsset.url } else { $sumAsset.browser_download_url }
        $sumPath = Join-Path $tempDir $sumAsset.name
        Invoke-WebRequest -Uri $sumUrl -Headers $dlHeaders -OutFile $sumPath
        $sumText = Get-Content -Path $sumPath -Raw -Encoding UTF8
        $expectedHash = Parse-Sha256Sums -Text $sumText -FileName $chosenAsset.name
        if (-not [string]::IsNullOrWhiteSpace($expectedHash)) {
            $actualHash = (Get-FileHash -Path $assetOut -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actualHash -ne $expectedHash) {
                throw "SHA-256 dogrulamasi basarisiz! Beklenen: $expectedHash, Gelen: $actualHash"
            }
            Write-Host "      SHA-256 dogrulandi." -ForegroundColor Green
        }
    }

    Write-Host "[4/4] '$InstallDir' dizinine kuruluyor ve Windows Arama/Kisayol kayitlari yapiliyor..." -ForegroundColor Gray
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    if ($chosenAsset.name -match 'setup|installer' -and $chosenAsset.name -match '\.exe$') {
        $allUsersArg = if ($needsAdmin) { "/allusers " } else { "" }
        Start-Process -FilePath $assetOut -ArgumentList "$allUsersArg/S /D=$InstallDir" -Wait
    } elseif ($chosenAsset.name -match '\.zip$') {
        Expand-Archive -Path $assetOut -DestinationPath $InstallDir -Force
    } else {
        $targetExe = Join-Path $InstallDir "Zaslon Browser.exe"
        Copy-Item -Path $assetOut -Destination $targetExe -Force
    }

    # Uygulama ici guncelleyicinin repo adini hazir gormesi icin tohum dosyasi (PAT token yazilmaz!)
    $seedJson = @{ repo = $Repo } | ConvertTo-Json
    Set-Content -Path (Join-Path $InstallDir "zaslon-github.json") -Value $seedJson -Encoding UTF8

    $mainExe = Get-ChildItem -Path $InstallDir -Filter "*.exe" -ErrorAction SilentlyContinue |
               Where-Object { $_.Name -match '^Zaslon' -and $_.Name -notmatch 'Uninstall' } | Select-Object -First 1
    if ($mainExe) {
        $desktopDir = if ($needsAdmin) { [Environment]::GetFolderPath("CommonDesktopDirectory") } else { [Environment]::GetFolderPath("Desktop") }
        if ([string]::IsNullOrWhiteSpace($desktopDir)) { $desktopDir = [Environment]::GetFolderPath("Desktop") }
        $startMenuDir = if ($needsAdmin) { Join-Path ([Environment]::GetFolderPath("CommonStartMenu")) "Programs" } else { Join-Path ([Environment]::GetFolderPath("StartMenu")) "Programs" }
        if ([string]::IsNullOrWhiteSpace($startMenuDir) -or -not (Test-Path $startMenuDir)) {
            $startMenuDir = Join-Path ([Environment]::GetFolderPath("StartMenu")) "Programs"
        }

        $desktopLink = Join-Path $desktopDir "Zaslon Browser.lnk"
        $startLink = Join-Path $startMenuDir "Zaslon Browser.lnk"
        New-Shortcut -ShortcutPath $desktopLink -TargetPath $mainExe.FullName -WorkingDir $InstallDir -Description "Zaslon Browser"
        New-Shortcut -ShortcutPath $startLink -TargetPath $mainExe.FullName -WorkingDir $InstallDir -Description "Zaslon Browser"

        Register-WindowsApp -ExePath $mainExe.FullName -DirPath $InstallDir -VersionStr ([string]$chosenRel.tag_name) -MachineWide (Test-IsAdmin)
        Refresh-WindowsShell
    }

    Write-Host ""
    Write-Host "[TAMAM] Zaslon Browser basariyla kuruldu: $InstallDir" -ForegroundColor Green
    Write-Host "        - Masaustu kisayolu ve Baslat Menusu (Windows Arama) eklendi." -ForegroundColor Gray
    Write-Host "        - Ayarlar > Hakkinda altindan istediginiz zaman guncellemeleri denetleyebilirsiniz." -ForegroundColor Gray
} finally {
    if (Test-Path $tempDir) {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
