#Requires -Version 5.1
<#
.SYNOPSIS
    Invoke-IRCollector — Kapsamli Windows Incident Response (IR) artefakt & log toplama scripti.

.DESCRIPTION
    Bir Windows sistemi (canli ya da boot edilmis klon) uzerinde calistirildiginda
    IR/forensic analiz icin gereken volatil ve volatil-olmayan tum verileri tek bir
    zaman damgali klasore toplar, her dosyanin SHA-256 hash'ini bir manifest'e yazar
    ve cikti klasorunu ZIP olarak paketler.

    Tasarim ilkeleri:
      * Her modul try/catch ile sarmalanir; bir modul patlasa bile toplama devam eder.
      * Tum aktivite zaman damgali bir log dosyasina + ekran transcript'ine yazilir.
      * Toplanan ham dosyalar (EVTX, registry hive, prefetch, amcache, srum...) hash'lenir.
      * Kilitli (live system) dosyalar icin opsiyonel VSS (Volume Shadow Copy) kullanir;
        klon offline/mount edilmisse ham kopya zaten calisir.

    DESTEKLENEN SENARYO: Yonetici (Administrator) PowerShell oturumunda calistirilir.

.PARAMETER OutputPath
    Ciktilarin yazilacagi kok klasor. Varsayilan: <SystemDrive>\IR_Collection

.PARAMETER DaysBack
    Zaman tabanli toplamada geriye dogru kac gunluk pencere kullanilacagi. Varsayilan: 7.
    Sunlari etkiler: (1) ham EVTX export'u XPath zaman filtresiyle bu pencereye indirilir,
    (2) parse edilen ozet event CSV'leri, (3) "supheli executable" ve "son degisen dosya" taramalari.
    NOT: Registry hive, Amcache, SRUDB, Prefetch, process/servis/persistence gibi
    "anlik durum (point-in-time)" artefaktlari bu pencereden bagimsiz olarak TAM toplanir.

.PARAMETER UseVSS
    Kilitli dosyalari (Amcache, SRUDB, NTUSER.DAT, tarayici DB'leri) kopyalamak icin
    Volume Shadow Copy snapshot olusturur. Canli sistemde onerilir.

.PARAMETER CollectRegistryHives
    SYSTEM/SOFTWARE/SAM/SECURITY ve kullanici NTUSER.DAT/UsrClass.dat hive'larini kopyalar.

.PARAMETER CollectBrowserArtifacts
    Chrome/Edge/Firefox gecmis, indirme, cerez, profil dosyalarini kopyalar.

.PARAMETER HashRunningBinaries
    Calisan process'lerin binary'lerini hash'ler ve imza (Authenticode) durumunu kontrol eder.

.PARAMETER NoCompress
    Sonda ZIP paketleme yapmaz.

.PARAMETER Full
    Tum agir modulleri acar: -UseVSS -CollectRegistryHives -CollectBrowserArtifacts -HashRunningBinaries.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Invoke-IRCollector.ps1 -Full

.EXAMPLE
    .\Invoke-IRCollector.ps1 -OutputPath D:\IR -DaysBack 7 -UseVSS

.NOTES
    Defensive / authorized IR use only.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $env:SystemDrive 'IR_Collection'),
    [int]$DaysBack = 7,
    [switch]$UseVSS,
    [switch]$CollectRegistryHives,
    [switch]$CollectBrowserArtifacts,
    [switch]$HashRunningBinaries,
    [switch]$CollectMFT,
    [switch]$NoCompress,
    [switch]$Full
)

# ---------------------------------------------------------------------------
#  Full anahtari: tum agir modulleri ac
# ---------------------------------------------------------------------------
if ($Full) {
    $UseVSS                  = $true
    $CollectRegistryHives    = $true
    $CollectBrowserArtifacts = $true
    $HashRunningBinaries     = $true
    $CollectMFT              = $true
}

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'   # hizi artirir

# Konsol cikti kodlamasini UTF-8'e al (banner block karakterleri + Turkce icin)
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
try { $OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
try { & chcp 65001 | Out-Null } catch {}

# ===========================================================================
#  0) BASLATMA / KLASOR YAPISI
# ===========================================================================
$HostName  = $env:COMPUTERNAME
$Stamp     = (Get-Date).ToString('yyyyMMdd_HHmmss')
$CaseRoot  = Join-Path $OutputPath ("IR_{0}_{1}" -f $HostName, $Stamp)
$SystemDrive = $env:SystemDrive                  # 'C:' varsayimini kaldirir (D:/E: sistem diski destegi)
$UsersRoot   = Join-Path $env:SystemDrive 'Users'

$Dirs = [ordered]@{
    Meta        = '00_Collection'
    System      = '01_System'
    Users       = '02_Users'
    Network     = '03_Network'
    Processes   = '04_Processes'
    Services    = '05_Services'
    Persistence = '06_Persistence'
    Tasks       = '07_ScheduledTasks'
    EventLogs   = '08_EventLogs'
    Registry    = '09_Registry'
    Forensic    = '10_Forensic_Artifacts'
    Browser     = '11_Browser'
    Defender    = '12_Defender_AV'
    FileSystem  = '13_FileSystem'
    PowerShell  = '14_PowerShell'
    Veeam       = '15_Veeam'
}

foreach ($d in $Dirs.Values) {
    $null = New-Item -ItemType Directory -Path (Join-Path $CaseRoot $d) -Force
}

$script:MetaDir   = Join-Path $CaseRoot $Dirs.Meta
$script:LogFile   = Join-Path $script:MetaDir 'collection.log'
$script:Manifest  = Join-Path $script:MetaDir 'manifest_sha256.csv'
$script:ManifestRows = New-Object System.Collections.Generic.List[object]
$script:VssLink   = $null
$script:VssDevice = $null    # ham (raw) NTFS okuma icin VSS GLOBALROOT cihaz yolu

# Manifest header
'FilePath,Size,SHA256,CollectedUtc' | Out-File -FilePath $script:Manifest -Encoding UTF8

# ===========================================================================
#  YARDIMCI FONKSIYONLAR
# ===========================================================================
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','OK')][string]$Level = 'INFO'
    )
    $ts   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[$ts][$Level] $Message"
    $color = switch ($Level) { 'OK' {'Green'} 'WARN' {'Yellow'} 'ERROR' {'Red'} default {'Gray'} }
    Write-Host $line -ForegroundColor $color
    try { Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 } catch {}
}

function Invoke-Module {
    param([string]$Name, [scriptblock]$Action)
    Write-Log "==> $Name" 'INFO'
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        & $Action
        $sw.Stop()
        Write-Log "    OK ($Name) [$([int]$sw.Elapsed.TotalSeconds)s]" 'OK'
    } catch {
        $sw.Stop()
        Write-Log "    HATA ($Name): $($_.Exception.Message)" 'ERROR'
    }
}

function Get-Out {
    # Modul kisaltmasindan tam yol uretir:  Get-Out System 'sysinfo.txt'
    param([string]$Key, [string]$File)
    Join-Path (Join-Path $CaseRoot $Dirs[$Key]) $File
}

function Save-Text {
    param($InputObject, [string]$Path, [int]$Width = 4096)
    $InputObject | Out-File -FilePath $Path -Encoding UTF8 -Width $Width
}

function Save-Csv {
    param($InputObject, [string]$Path)
    # null/bos girdiye dayanikli: pipeline'a $null gitmesini engelle
    $items = @($InputObject) | Where-Object { $null -ne $_ }
    if ($items.Count -eq 0) {
        Set-Content -Path $Path -Value 'NO_DATA' -Encoding UTF8
        return
    }
    $items | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
}

function Save-Json {
    param($InputObject, [string]$Path, [int]$Depth = 6)
    $InputObject | ConvertTo-Json -Depth $Depth | Out-File -FilePath $Path -Encoding UTF8
}

function Add-Manifest {
    param([string]$Path)
    try {
        $fi = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($fi.PSIsContainer) { return }
        $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
        $row = '"{0}",{1},{2},{3}' -f $fi.FullName, $fi.Length, $hash, (Get-Date).ToUniversalTime().ToString('o')
        Add-Content -Path $script:Manifest -Value $row -Encoding UTF8
    } catch {
        Write-Log "    Manifest/hash basarisiz: $Path -> $($_.Exception.Message)" 'WARN'
    }
}

function Copy-Artifact {
    <#
        Tek bir dosyayi kopyalar; kilitliyse VSS uzerinden dener; sonra hash'leyip manifest'e ekler.
        $SourcePath: kaynak (live) yol; $DestPath: hedef dosya yolu.
    #>
    param([string]$SourcePath, [string]$DestPath, [switch]$PreferVSS)
    try {
        $dst = Split-Path $DestPath -Parent
        if (-not (Test-Path $dst)) { $null = New-Item -ItemType Directory -Path $dst -Force }

        $copied = $false
        if ($PreferVSS -and $script:VssLink) {
            $vssSrc = Get-VssPath $SourcePath
            if ($vssSrc -and (Test-Path -LiteralPath $vssSrc)) {
                Copy-Item -LiteralPath $vssSrc -Destination $DestPath -Force -ErrorAction Stop
                $copied = $true
            }
        }
        if (-not $copied) {
            Copy-Item -LiteralPath $SourcePath -Destination $DestPath -Force -ErrorAction Stop
            $copied = $true
        }
        if ($copied) { Add-Manifest $DestPath }
    } catch {
        # Direkt kopya kilitliyse VSS'i son care olarak dene
        if ($script:VssLink) {
            try {
                $vssSrc = Get-VssPath $SourcePath
                if ($vssSrc -and (Test-Path -LiteralPath $vssSrc)) {
                    Copy-Item -LiteralPath $vssSrc -Destination $DestPath -Force -ErrorAction Stop
                    Add-Manifest $DestPath
                    return
                }
            } catch {}
        }
        Write-Log "    Kopyalanamadi: $SourcePath -> $($_.Exception.Message)" 'WARN'
    }
}

function Copy-Tree {
    # Klasoru robocopy ile guvenli kopyalar (cogu kucuk dosya icin idealdir)
    param([string]$Source, [string]$Dest, [string]$FileFilter = '*.*')
    if (-not (Test-Path -LiteralPath $Source)) { return }
    $null = New-Item -ItemType Directory -Path $Dest -Force
    # robocopy exit code 0-7 basarilidir
    & robocopy $Source $Dest $FileFilter /E /COPY:DAT /R:1 /W:1 /NFL /NDL /NJH /NJS /NP /XJ | Out-Null
    Get-ChildItem -LiteralPath $Dest -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object { Add-Manifest $_.FullName }
}

function Get-UserProfileDirs {
    # Gercek kullanici profil dizinleri (DirectoryInfo). C: varsayimi YOK.
    # Once Win32_UserProfile (sistem diskinden bagimsiz, kesin); olmazsa $UsersRoot enumerasyonu.
    $dirs = @()
    try {
        $dirs = Get-CimInstance Win32_UserProfile -ErrorAction Stop |
            Where-Object { $_.LocalPath -and -not $_.Special } |
            ForEach-Object { Get-Item -LiteralPath $_.LocalPath -ErrorAction SilentlyContinue }
    } catch {}
    if (-not $dirs) {
        $dirs = Get-ChildItem -LiteralPath $UsersRoot -Directory -ErrorAction SilentlyContinue
    }
    $dirs | Where-Object { $_ } | Sort-Object FullName -Unique
}

function Show-Banner {
    $b = @'

  ██╗███╗   ██╗███████╗     ██╗██████╗
  ██║████╗  ██║██╔════╝     ██║██╔══██╗
  ██║██╔██╗ ██║█████╗       ██║██████╔╝
  ██║██║╚██╗██║██╔══╝       ██║██╔══██╗
  ██║██║ ╚████║██║          ██║██║  ██║
  ╚═╝╚═╝  ╚═══╝╚═╝          ╚═╝╚═╝  ╚═╝
'@
    Write-Host $b -ForegroundColor Cyan
    Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
    Write-Host "  ║   InfinitumIT  ·  Incident Response Collector  v1.0       ║" -ForegroundColor White
    Write-Host "  ║   Defensive / Authorized IR Use Only                     ║" -ForegroundColor Gray
    Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor DarkCyan
    Write-Host ("   Host : {0}" -f $env:COMPUTERNAME)                  -ForegroundColor DarkGray
    Write-Host ("   User : {0}" -f $env:USERNAME)                      -ForegroundColor DarkGray
    Write-Host ("   Time : {0}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')) -ForegroundColor DarkGray
    Write-Host ("   Out  : {0}" -f $CaseRoot)                          -ForegroundColor DarkGray
    Write-Host ""
}

# ---- VSS (Volume Shadow Copy) yardimcilari ----
function Get-VssPath {
    param([string]$LivePath)
    if (-not $script:VssLink) { return $null }
    # C:\Windows\... -> <vsslink>\Windows\...
    if ($LivePath -match '^[A-Za-z]:\\(.*)$') {
        return (Join-Path $script:VssLink $Matches[1])
    }
    return $null
}

function New-VssSnapshot {
    param([string]$Drive = $env:SystemDrive)
    try {
        Write-Log "VSS snapshot olusturuluyor ($Drive)..." 'INFO'
        $cls = [WMICLASS]'root\cimv2:Win32_ShadowCopy'
        $res = $cls.Create("$Drive\", 'ClientAccessible')
        if ($res.ReturnValue -ne 0) { throw "Win32_ShadowCopy.Create donus kodu: $($res.ReturnValue)" }
        $sc  = Get-CimInstance Win32_ShadowCopy | Where-Object { $_.ID -eq $res.ShadowID }
        if (-not $sc) { throw 'Snapshot bulunamadi.' }
        $device = $sc.DeviceObject    # \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN
        $link   = Join-Path $env:TEMP ('vss_' + [guid]::NewGuid().ToString('N'))
        # mklink hedefi backslash ile bitmeli
        & cmd /c mklink /d "`"$link`"" "`"$device\`"" | Out-Null
        if (Test-Path -LiteralPath $link) {
            $script:VssLink   = $link
            $script:VssDevice = $device
            Write-Log "VSS hazir: $link" 'OK'
        } else {
            throw 'Symlink olusturulamadi.'
        }
    } catch {
        Write-Log "VSS olusturulamadi (kilitli dosyalar atlanacak): $($_.Exception.Message)" 'WARN'
        $script:VssLink = $null
    }
}

function Remove-VssSnapshot {
    if ($script:VssLink -and (Test-Path -LiteralPath $script:VssLink)) {
        try { & cmd /c rmdir "`"$script:VssLink`"" | Out-Null } catch {}
    }
    # Olusturulan shadow copy'i de silmek istersek (opsiyonel; analizde isimize yarayabilir, biraktik)
}

# ---- Ham NTFS metafile toplama ($MFT, $UsnJrnl) ----
$script:RawNtfsReady = $false
function Initialize-RawNtfs {
    if ($script:RawNtfsReady) { return $true }
    $code = @'
using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class RawNtfs {
    [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr sec, uint disp, uint flags, IntPtr tmpl);
    static int _bps = 512;
    public static void DumpMft(string volume, string outPath) {
        var h = CreateFileW(volume, 0x80000000u, 0x00000001u | 0x00000002u, IntPtr.Zero, 3u, 0u, IntPtr.Zero);
        if (h.IsInvalid) throw new IOException("CreateFile basarisiz: " + Marshal.GetLastWin32Error());
        using (var fs = new FileStream(h, FileAccess.Read)) {
            byte[] vbr = ReadAt(fs, 0, 512, 512);
            _bps = BitConverter.ToUInt16(vbr, 0x0B); if (_bps <= 0) _bps = 512;
            int spc = vbr[0x0D]; if (spc <= 0) spc = 8;
            long clusterSize = (long)_bps * spc;
            long mftLcn = BitConverter.ToInt64(vbr, 0x30);
            byte[] rec = ReadAt(fs, mftLcn * clusterSize, 1024, _bps);
            ApplyFixup(rec);
            var runs = new List<long[]>();
            int p = BitConverter.ToUInt16(rec, 0x14);
            while (p + 8 <= rec.Length) {
                uint type = BitConverter.ToUInt32(rec, p);
                if (type == 0xFFFFFFFF) break;
                int len = BitConverter.ToInt32(rec, p + 4);
                if (len <= 0) break;
                if (type == 0x80) {
                    if (rec[p + 8] == 1) ParseRuns(rec, p + BitConverter.ToUInt16(rec, p + 0x20), runs);
                    break;
                }
                p += len;
            }
            using (var outFs = new FileStream(outPath, FileMode.Create, FileAccess.Write)) {
                long curLcn = 0;
                foreach (var run in runs) {
                    curLcn += run[0];
                    long bytes = run[1] * clusterSize, pos = curLcn * clusterSize, done = 0;
                    while (done < bytes) {
                        int chunk = (int)Math.Min(1 << 20, bytes - done);
                        byte[] buf = ReadAt(fs, pos + done, chunk, _bps);
                        outFs.Write(buf, 0, chunk);
                        done += chunk;
                    }
                }
            }
        }
    }
    static byte[] ReadAt(FileStream fs, long off, int len, int align) {
        long aOff = off - (off % align);
        int delta = (int)(off - aOff);
        int toRead = ((delta + len + align - 1) / align) * align;
        fs.Seek(aOff, SeekOrigin.Begin);
        byte[] tmp = new byte[toRead];
        int r = 0; while (r < toRead) { int n = fs.Read(tmp, r, toRead - r); if (n <= 0) break; r += n; }
        byte[] o = new byte[len]; Array.Copy(tmp, delta, o, 0, len); return o;
    }
    static void ApplyFixup(byte[] rec) {
        int usaOff = BitConverter.ToUInt16(rec, 0x04), usaCnt = BitConverter.ToUInt16(rec, 0x06);
        for (int i = 1; i < usaCnt; i++) {
            int end = i * _bps - 2;
            if (end + 2 > rec.Length || usaOff + i * 2 + 2 > rec.Length) break;
            rec[end] = rec[usaOff + i * 2]; rec[end + 1] = rec[usaOff + i * 2 + 1];
        }
    }
    static void ParseRuns(byte[] rec, int p, List<long[]> runs) {
        while (p < rec.Length) {
            byte hdr = rec[p++]; if (hdr == 0) break;
            int lenB = hdr & 0x0F, offB = (hdr >> 4) & 0x0F;
            if (p + lenB + offB > rec.Length) break;
            long rl = 0; for (int i = 0; i < lenB; i++) rl |= (long)rec[p + i] << (8 * i); p += lenB;
            long ro = 0; for (int i = 0; i < offB; i++) ro |= (long)rec[p + i] << (8 * i);
            if (offB > 0 && (rec[p + offB - 1] & 0x80) != 0) for (int i = offB; i < 8; i++) ro |= (long)0xFF << (8 * i);
            p += offB;
            runs.Add(new long[] { ro, rl });
        }
    }
}
'@
    try { Add-Type -TypeDefinition $code -ErrorAction Stop; $script:RawNtfsReady = $true; return $true }
    catch { Write-Log "    Raw-NTFS modulu derlenemedi: $($_.Exception.Message)" 'WARN'; return $false }
}

function Copy-UsnJournal {
    param([string]$Volume, [string]$OutFile)   # Volume orn. 'C:'
    try {
        & fsutil usn readjournal "$Volume" csv 2>$null | Out-File -FilePath $OutFile -Encoding UTF8
        if (-not ((Test-Path $OutFile) -and (Get-Item $OutFile).Length -gt 0)) {
            & fsutil usn readjournal "$Volume" 2>$null | Out-File -FilePath $OutFile -Encoding UTF8   # eski fsutil fallback
        }
        if ((Test-Path $OutFile) -and (Get-Item $OutFile).Length -gt 0) { Add-Manifest $OutFile; return $true }
    } catch { Write-Log "    USN journal alinamadi: $($_.Exception.Message)" 'WARN' }
    return $false
}

function Copy-MasterFileTable {
    param([string]$OutFile)
    # 1) Harici arac (RawCopy*.exe) script klasorunde varsa -> en saglam
    try {
        $scriptDir = Split-Path -Parent $PSCommandPath
        $rawcopy = Get-ChildItem -LiteralPath $scriptDir -Filter 'RawCopy*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($rawcopy) {
            $outDir = Split-Path $OutFile
            & $rawcopy.FullName "/FileNamePath:$SystemDrive\`$MFT" "/OutputPath:$outDir" 2>$null
            $cand = Join-Path $outDir '$MFT'
            if (Test-Path -LiteralPath $cand) { Move-Item -LiteralPath $cand -Destination $OutFile -Force; Add-Manifest $OutFile; return $true }
        }
    } catch {}
    # 2) Native ham okuma (best-effort): once VSS cihazindan, yoksa canli birimden
    if (-not (Initialize-RawNtfs)) { return $false }
    $vol = if ($script:VssDevice) { $script:VssDevice } else { "\\.\$SystemDrive" }
    try {
        [RawNtfs]::DumpMft($vol, $OutFile)
        if ((Test-Path $OutFile) -and (Get-Item $OutFile).Length -gt 0) { Add-Manifest $OutFile; return $true }
    } catch { Write-Log "    `$MFT ham kopya basarisiz (MFTECmd/RawCopy onerilir): $($_.Exception.Message)" 'WARN' }
    return $false
}

# ===========================================================================
#  TRANSCRIPT + YONETICI KONTROLU
# ===========================================================================
try { Start-Transcript -Path (Join-Path $script:MetaDir 'transcript.txt') -Force | Out-Null } catch {}

Show-Banner

$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
Write-Log "===== Invoke-IRCollector baslatildi =====" 'INFO'
Write-Log "Host: $HostName | Kullanici: $env:USERNAME | Admin: $IsAdmin" 'INFO'
Write-Log "Cikti: $CaseRoot" 'INFO'
if (-not $IsAdmin) { Write-Log "UYARI: Yonetici degilsiniz. Cogu modul eksik/bos toplanacaktir!" 'WARN' }

if ($UseVSS) {
    if ($IsAdmin) { New-VssSnapshot -Drive $env:SystemDrive } else { Write-Log "VSS icin admin gerekli; atlandi." 'WARN' }
}

# ===========================================================================
#  1) SISTEM BILGISI
# ===========================================================================
Invoke-Module 'Sistem Bilgisi' {
    $os  = Get-CimInstance Win32_OperatingSystem
    $cs  = Get-CimInstance Win32_ComputerSystem
    $bios= Get-CimInstance Win32_BIOS

    $info = [ordered]@{
        Hostname        = $env:COMPUTERNAME
        OS              = $os.Caption
        Version         = $os.Version
        Build           = $os.BuildNumber
        Architecture    = $os.OSArchitecture
        InstallDate     = $os.InstallDate
        LastBootUpTime  = $os.LastBootUpTime
        SystemUptime    = (New-TimeSpan -Start $os.LastBootUpTime -End (Get-Date)).ToString()
        TimeZone        = (Get-TimeZone).Id
        Domain          = $cs.Domain
        PartOfDomain    = $cs.PartOfDomain
        Manufacturer    = $cs.Manufacturer
        Model           = $cs.Model
        SerialNumber    = $bios.SerialNumber
        BIOSVersion     = ($bios.SMBIOSBIOSVersion)
        TotalRAM_GB     = [math]::Round($cs.TotalPhysicalMemory/1GB,2)
        CurrentUser     = $env:USERNAME
        CollectionTimeUtc = (Get-Date).ToUniversalTime().ToString('o')
    }
    Save-Json $info (Get-Out System 'system_info.json')
    Save-Text (systeminfo) (Get-Out System 'systeminfo_native.txt')

    Save-Csv (Get-HotFix | Select-Object HotFixID, Description, InstalledBy, InstalledOn) (Get-Out System 'hotfixes.csv')
    Save-Text (Get-ChildItem Env: | Sort-Object Name | Format-Table -AutoSize | Out-String) (Get-Out System 'environment_variables.txt')

    # Disk & birim
    Save-Csv (Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID,DriveType,FileSystem,@{N='Size_GB';E={[math]::Round($_.Size/1GB,2)}},@{N='Free_GB';E={[math]::Round($_.FreeSpace/1GB,2)}},VolumeSerialNumber) (Get-Out System 'disks.csv')

    # Yuklu yazilim (registry uninstall)
    $uninstallKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $sw = foreach ($k in $uninstallKeys) {
        Get-ItemProperty $k -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation
    }
    Save-Csv ($sw | Sort-Object DisplayName -Unique) (Get-Out System 'installed_software.csv')
}

# ===========================================================================
#  1b) UYGULAMA KONFIGURASYONU — Veeam Backup & Replication
#      (DataMover / Linux Deployer / Protection Group Deployer port'lari +
#       tum Veeam registry agaci + ham .reg export)
# ===========================================================================
Invoke-Module 'Uygulama Konfig (Veeam B&R)' {
    $brKeys = @(
        'HKLM:\SOFTWARE\Veeam\Veeam Backup and Replication',
        'HKLM:\SOFTWARE\Wow6432Node\Veeam\Veeam Backup and Replication'
    )
    $veeamRoots    = @('HKLM:\SOFTWARE\Veeam', 'HKLM:\SOFTWARE\Wow6432Node\Veeam')
    $veeamRootsReg = @('HKLM\SOFTWARE\Veeam', 'HKLM\SOFTWARE\Wow6432Node\Veeam')

    # 1) Sorulan spesifik port degerleri + faydali ek alanlar
    $portRows = foreach ($k in $brKeys) {
        if (Test-Path $k) {
            $vb = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
            [pscustomobject]@{
                Key                                  = $k
                AMCustomDataMoverPort                = $vb.AMCustomDataMoverPort
                AMCustomLinuxDeployerPort            = $vb.AMCustomLinuxDeployerPort
                AMProtectionGroupCustomDeployerPort  = $vb.AMProtectionGroupCustomDeployerPort
                SqlServerName                        = $vb.SqlServerName
                SqlInstanceName                      = $vb.SqlInstanceName
                SqlDatabaseName                      = $vb.SqlDatabaseName
                CorePath                             = $vb.CorePath
                LogDirectory                         = $vb.LogDirectory
            }
        }
    }
    if ($portRows) {
        Save-Json $portRows (Get-Out System 'veeam_br_ports.json')
        Write-Log "    Veeam B&R port'lari okundu." 'OK'
    } else {
        Write-Log "    Veeam B&R anahtari bulunamadi (kurulu degil olabilir)." 'WARN'
    }

    # 2) Tum Veeam alt agacini recursive oku -> JSON (degerleriyle)
    $all = foreach ($r in $veeamRoots) {
        if (Test-Path $r) {
            Get-ChildItem $r -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                $vals = @{}
                if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { $vals[$_.Name] = $_.Value } }
                [pscustomobject]@{ Key = $_.Name; Values = $vals }
            }
        }
    }
    if ($all) { Save-Json $all (Get-Out System 'veeam_full_tree.json') 8 }

    # 3) Ham .reg export (analist offline incelesin)
    foreach ($r in $veeamRootsReg) {
        $name = (($r -replace '[\\ ]','_')) + '.reg'
        $dst  = Get-Out System $name
        try {
            & reg export $r "$dst" /y 2>$null
            if (Test-Path $dst) { Add-Manifest $dst }
        } catch {}
    }
}

# ===========================================================================
#  1c) VEEAM DERIN TOPLAMA — loglar, servisler, surum, process'ler
#      (Veeam = fidye yazilimi #1 hedefi: credential theft + yedek silme.
#       Sadece Veeam yollari varsa is yapar; diger makinelerde hizlica bos gecer.)
# ===========================================================================
Invoke-Module 'Veeam Derin Toplama' {
    $vDir = Join-Path $CaseRoot $Dirs.Veeam

    # 1) Veeam servisleri (calistigi hesap + binary yolu)
    $vsvc = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'Veeam' -or $_.PathName -match 'Veeam' } |
        Select-Object Name, DisplayName, State, StartMode, StartName, PathName, ProcessId
    Save-Csv $vsvc (Join-Path $vDir 'veeam_services.csv')

    # 2) Yuklu Veeam bilesenleri / surum (build numarasi -> CVE eslemesi icin onemli)
    $vsw = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match 'Veeam' } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation
    Save-Csv $vsw (Join-Path $vDir 'veeam_components.csv')

    # 3) Calisan Veeam process'leri (komut satiriyla — anormal cocuk process tespiti)
    $vproc = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'Veeam' -or $_.ExecutablePath -match 'Veeam' } |
        Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate
    Save-Csv $vproc (Join-Path $vDir 'veeam_processes.csv')

    # 4) Veeam loglari (ProgramData\Veeam) — son $DaysBack gun, TOPLAM boyut tavanli
    $logRoot = (Join-Path $env:ProgramData 'Veeam')
    $cut     = (Get-Date).AddDays(-1 * $DaysBack)
    $logDst  = Join-Path $vDir 'Logs'
    $null    = New-Item -ItemType Directory -Path $logDst -Force
    $maxTotalMB = 1024            # 1 GB tavan; asilinca log kopyalama durur (envanter yine tam)
    $sumBytes   = 0
    if (Test-Path $logRoot) {
        Get-ChildItem $logRoot -Recurse -File -Include *.log -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt $cut } |
            Sort-Object LastWriteTime -Descending |
            ForEach-Object {
                if ($sumBytes -lt ($maxTotalMB * 1MB)) {
                    $rel = $_.FullName.Substring(3)        # bastaki "C:\" at
                    $dst = Join-Path $logDst $rel
                    $null = New-Item -ItemType Directory -Path (Split-Path $dst -Parent) -Force
                    try { Copy-Item -LiteralPath $_.FullName -Destination $dst -Force -ErrorAction Stop; Add-Manifest $dst; $sumBytes += $_.Length } catch {}
                }
            }
        Write-Log ("    Veeam log kopyalandi: ~{0} MB (tavan {1} MB)" -f [int]($sumBytes/1MB), $maxTotalMB) 'OK'
    } else {
        Write-Log "    $logRoot yok (bu makinede Veeam log dizini bulunamadi)." 'WARN'
    }

    # 5) Tum Veeam log dizini envanteri (kopyalanmayanlar dahil) — neyin var oldugunu gosterir
    if (Test-Path $logRoot) {
        Save-Csv (Get-ChildItem $logRoot -Recurse -File -ErrorAction SilentlyContinue |
            Select-Object FullName, Length, CreationTime, LastWriteTime | Sort-Object LastWriteTime -Descending) (Join-Path $vDir 'veeam_log_inventory.csv')
    }

    # 6) Yerel Veeam SQL/Postgres instance'i var mi? (config DB ipucu)
    $sqlInst = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'VEEAMSQL|postgres|MSSQL\$VEEAM' } |
        Select-Object Name, DisplayName, State, StartName, PathName
    Save-Csv $sqlInst (Join-Path $vDir 'veeam_db_instances.csv')
}

# ===========================================================================
#  2) KULLANICILAR & HESAPLAR
# ===========================================================================
Invoke-Module 'Kullanicilar & Hesaplar' {
    Save-Text (whoami /all) (Get-Out Users 'whoami_all.txt')

    try {
        Save-Csv (Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordLastSet,PasswordExpires,SID,Description) (Get-Out Users 'local_users.csv')
        Save-Csv (Get-LocalGroup | Select-Object Name,SID,Description) (Get-Out Users 'local_groups.csv')
        $grpMembers = foreach ($g in (Get-LocalGroup)) {
            try { Get-LocalGroupMember -Group $g.Name -ErrorAction Stop | Select-Object @{N='Group';E={$g.Name}},Name,ObjectClass,PrincipalSource,SID } catch {}
        }
        Save-Csv $grpMembers (Get-Out Users 'local_group_members.csv')
    } catch {
        # PS 5.1 oncesi / Get-LocalUser yoksa native fallback
        Save-Text (net user)              (Get-Out Users 'net_user.txt')
        Save-Text (net localgroup)        (Get-Out Users 'net_localgroup.txt')
        Save-Text (net localgroup administrators) (Get-Out Users 'net_localgroup_administrators.txt')
    }

    # Profil klasorleri (lateral movement / yeni hesap tespiti)
    Save-Csv (Get-CimInstance Win32_UserProfile | Select-Object LocalPath,SID,LastUseTime,Special,Loaded) (Get-Out Users 'user_profiles.csv')

    # Aktif oturumlar
    Save-Text (& query user 2>$null)  (Get-Out Users 'query_user.txt')
    Save-Csv (Get-CimInstance Win32_LoggedOnUser | Select-Object Antecedent,Dependent) (Get-Out Users 'logged_on_users.csv')
}

# ===========================================================================
#  3) AG (NETWORK)
# ===========================================================================
Invoke-Module 'Ag Yapilandirmasi & Baglantilar' {
    Save-Text (ipconfig /all)         (Get-Out Network 'ipconfig_all.txt')
    Save-Text (arp -a)                (Get-Out Network 'arp.txt')
    Save-Text (route print)           (Get-Out Network 'route_print.txt')
    Save-Text (netstat -anob)         (Get-Out Network 'netstat_anob.txt')   # PID + process (admin)
    Save-Text (ipconfig /displaydns)  (Get-Out Network 'dns_cache.txt')
    Save-Text (nbtstat -c 2>$null)    (Get-Out Network 'nbtstat_cache.txt')
    Save-Text (net use)               (Get-Out Network 'net_use.txt')
    Save-Text (net share)             (Get-Out Network 'net_share.txt')

    # Aktif TCP baglantilarini process'e maple
    try {
        $procMap = @{}
        Get-CimInstance Win32_Process | ForEach-Object { $procMap[[int]$_.ProcessId] = $_ }
        $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object {
            $p = $procMap[[int]$_.OwningProcess]
            [pscustomobject]@{
                LocalAddress  = $_.LocalAddress
                LocalPort     = $_.LocalPort
                RemoteAddress = $_.RemoteAddress
                RemotePort    = $_.RemotePort
                State         = $_.State
                PID           = $_.OwningProcess
                ProcessName   = if ($p) { $p.Name } else { '' }
                ProcessPath   = if ($p) { $p.ExecutablePath } else { '' }
                CommandLine   = if ($p) { $p.CommandLine } else { '' }
            }
        }
        Save-Csv ($conns | Sort-Object State,RemoteAddress) (Get-Out Network 'tcp_connections.csv')
    } catch {}

    Save-Csv (Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,OwningProcess) (Get-Out Network 'udp_listeners.csv')
    Save-Csv (Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object Entry,Name,Data,Type,TimeToLive) (Get-Out Network 'dns_cache.csv')
    Save-Csv (Get-NetNeighbor -ErrorAction SilentlyContinue | Select-Object IPAddress,LinkLayerAddress,State,InterfaceAlias) (Get-Out Network 'arp_neighbors.csv')

    # SMB paylasim / oturum
    Save-Csv (Get-SmbShare -ErrorAction SilentlyContinue | Select-Object Name,Path,Description) (Get-Out Network 'smb_shares.csv')
    Save-Csv (Get-SmbSession -ErrorAction SilentlyContinue | Select-Object ClientComputerName,ClientUserName,NumOpens) (Get-Out Network 'smb_sessions.csv')
    Save-Csv (Get-SmbConnection -ErrorAction SilentlyContinue | Select-Object ServerName,ShareName,UserName,Dialect) (Get-Out Network 'smb_connections.csv')

    # Guvenlik duvari (kural seti + aktif profiller). Saldirganlar buraya kural ekler!
    Save-Text (& netsh advfirewall firewall show rule name=all)  (Get-Out Network 'firewall_rules.txt')
    Save-Text (& netsh advfirewall show allprofiles)             (Get-Out Network 'firewall_profiles.txt')

    # WiFi profilleri
    Save-Text (& netsh wlan show profiles 2>$null)               (Get-Out Network 'wlan_profiles.txt')

    # Hosts dosyasi (DNS hijack / C2 yonlendirme tespiti)
    Copy-Artifact "$env:WINDIR\System32\drivers\etc\hosts" (Get-Out Network 'hosts')

    # Proxy ayarlari
    Save-Text (& netsh winhttp show proxy) (Get-Out Network 'winhttp_proxy.txt')
}

# ===========================================================================
#  4) PROCESS'LER
# ===========================================================================
Invoke-Module 'Calisan Process listesi' {
    $cim = Get-CimInstance Win32_Process
    $rows = foreach ($p in $cim) {
        $owner = $null
        try { $owner = (Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction SilentlyContinue) } catch {}
        [pscustomobject]@{
            PID          = $p.ProcessId
            ParentPID    = $p.ParentProcessId
            Name         = $p.Name
            Path         = $p.ExecutablePath
            CommandLine  = $p.CommandLine
            Owner        = if ($owner) { "$($owner.Domain)\$($owner.User)" } else { '' }
            CreationDate = $p.CreationDate
            SessionId    = $p.SessionId
        }
    }
    Save-Csv ($rows | Sort-Object PID) (Get-Out Processes 'processes.csv')

    # Process agaci (parent-child)
    $tree = $rows | Sort-Object ParentPID, PID | Select-Object ParentPID, PID, Name, Path, CommandLine
    Save-Text ($tree | Format-Table -AutoSize | Out-String -Width 4096) (Get-Out Processes 'process_tree.txt')

    # Opsiyonel: binary hash + imza dogrulama (unsigned/anormal binary tespiti)
    if ($HashRunningBinaries) {
        Write-Log "    Process binary'leri hash'leniyor + imza kontrolu..." 'INFO'
        $hashRows = foreach ($p in ($rows | Where-Object { $_.Path } | Sort-Object Path -Unique)) {
            $sha = ''; $sig = ''; $signer = ''
            try { $sha = (Get-FileHash -LiteralPath $p.Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}
            try {
                $s = Get-AuthenticodeSignature -LiteralPath $p.Path -ErrorAction Stop
                $sig = $s.Status; $signer = $s.SignerCertificate.Subject
            } catch {}
            [pscustomobject]@{ Path=$p.Path; Name=$p.Name; SHA256=$sha; SignatureStatus=$sig; Signer=$signer }
        }
        Save-Csv $hashRows (Get-Out Processes 'process_binaries_hash_signature.csv')
    }

    # Yuklu moduller (DLL) — fileless/injection ipuclari
    try {
        $mods = Get-Process | Where-Object { $_.Path } | ForEach-Object {
            $proc = $_
            $proc.Modules | ForEach-Object {
                [pscustomobject]@{ ProcessName=$proc.Name; PID=$proc.Id; ModuleName=$_.ModuleName; FileName=$_.FileName; Company=$_.Company }
            }
        }
        Save-Csv $mods (Get-Out Processes 'loaded_modules.csv')
    } catch {}
}

# ===========================================================================
#  5) SERVISLER
# ===========================================================================
Invoke-Module 'Servisler' {
    $svc = Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, StartName, PathName, ServiceType, ProcessId, Description
    Save-Csv ($svc | Sort-Object Name) (Get-Out Services 'services.csv')

    # Supheli: kullanici dizininden/temp'ten calisan, unquoted path, svchost disi
    $suspicious = $svc | Where-Object {
        $_.PathName -match '\\Users\\|\\Temp\\|\\AppData\\|\\ProgramData\\|powershell|cmd\.exe|\.bat|\.vbs|\.ps1|rundll32|regsvr32|mshta'
    }
    Save-Csv $suspicious (Get-Out Services 'services_suspicious.csv')
}

# ===========================================================================
#  6) PERSISTENCE (KALICILIK MEKANIZMALARI)
# ===========================================================================
Invoke-Module 'Persistence / Autoruns' {
    # Win32_StartupCommand (Run keys + startup folder ozetlenmis)
    Save-Csv (Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User) (Get-Out Persistence 'startup_commands.csv')

    # Kritik registry autorun anahtarlari
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    )
    $runRows = foreach ($k in $runKeys) {
        if (Test-Path $k) {
            $props = Get-ItemProperty $k -ErrorAction SilentlyContinue
            $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                [pscustomobject]@{ Key=$k; Name=$_.Name; Value=$_.Value }
            }
        }
    }
    Save-Csv $runRows (Get-Out Persistence 'run_keys.csv')

    # Winlogon (Shell/Userinit/Notify hijack)
    $winlogon = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
    Save-Json ($winlogon | Select-Object Shell,Userinit,Taskman,VmApplet,System,AppSetup) (Get-Out Persistence 'winlogon.json')

    # Image File Execution Options (debugger hijack / accessibility backdoor)
    $ifeo = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue |
        ForEach-Object {
            $d = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if ($d.Debugger -or $d.GlobalFlag) { [pscustomobject]@{ Image=$_.PSChildName; Debugger=$d.Debugger; GlobalFlag=$d.GlobalFlag } }
        }
    Save-Csv $ifeo (Get-Out Persistence 'ifeo_debuggers.csv')

    # AppInit_DLLs / AppCertDlls
    $appinit = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -ErrorAction SilentlyContinue
    Save-Json ($appinit | Select-Object AppInit_DLLs,LoadAppInit_DLLs) (Get-Out Persistence 'appinit_dlls.json')

    # LSA paketleri (auth/security packages — credential theft persistence)
    $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
    Save-Json ($lsa | Select-Object 'Authentication Packages','Security Packages','Notification Packages') (Get-Out Persistence 'lsa_packages.json')

    # Startup klasorleri (tum kullanicilar + ortak)
    $startupDirs = @(
        (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup')
    )
    Get-UserProfileDirs | ForEach-Object {
        $startupDirs += (Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup')
    }
    $startupItems = foreach ($d in $startupDirs) {
        if (Test-Path $d) { Get-ChildItem $d -File -Recurse -ErrorAction SilentlyContinue | Select-Object FullName,Length,CreationTime,LastWriteTime }
    }
    Save-Csv $startupItems (Get-Out Persistence 'startup_folder_items.csv')

    # WMI kalici event subscription (gelismis persistence)
    try {
        $f = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
        $c = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue
        $b = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue
        Save-Json @{ EventFilters=$f; EventConsumers=$c; Bindings=$b } (Get-Out Persistence 'wmi_subscriptions.json') 8
    } catch {}

    # BITS transferleri (indirme persistence/C2)
    Save-Text (& bitsadmin /list /allusers /verbose 2>$null) (Get-Out Persistence 'bits_jobs.txt')
}

# ===========================================================================
#  7) ZAMANLANMIS GOREVLER
# ===========================================================================
Invoke-Module 'Zamanlanmis Gorevler' {
    Save-Text (& schtasks /query /fo LIST /v 2>$null) (Get-Out Tasks 'schtasks_verbose.txt')
    try {
        $tasks = Get-ScheduledTask | ForEach-Object {
            $info = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
            [pscustomobject]@{
                TaskName    = $_.TaskName
                TaskPath    = $_.TaskPath
                State       = $_.State
                Author      = $_.Author
                Actions     = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
                Triggers    = ($_.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ', '
                RunAsUser   = $_.Principal.UserId
                LastRunTime = $info.LastRunTime
                NextRunTime = $info.NextRunTime
            }
        }
        Save-Csv $tasks (Get-Out Tasks 'scheduled_tasks.csv')
    } catch {}

    # Ham gorev XML'leri (C:\Windows\System32\Tasks)
    Copy-Tree "$env:WINDIR\System32\Tasks" (Get-Out Tasks 'Tasks_raw')
}

# ===========================================================================
#  8) EVENT LOG'LAR (Ham EVTX export + parse edilmis CSV)
# ===========================================================================
Invoke-Module 'Event Loglar (EVTX export)' {
    $evtxDir = Join-Path (Join-Path $CaseRoot $Dirs.EventLogs) 'EVTX'
    $null = New-Item -ItemType Directory -Path $evtxDir -Force

    $channels = @(
        'Security','System','Application','Setup',
        'Windows PowerShell',
        'Microsoft-Windows-PowerShell/Operational',
        'Microsoft-Windows-Sysmon/Operational',
        'Microsoft-Windows-TaskScheduler/Operational',
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
        'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational',
        'Microsoft-Windows-Windows Defender/Operational',
        'Microsoft-Windows-WMI-Activity/Operational',
        'Microsoft-Windows-Bits-Client/Operational',
        'Microsoft-Windows-WinRM/Operational',
        'Microsoft-Windows-DNS-Client/Operational',
        'Microsoft-Windows-SMBClient/Security',
        'Microsoft-Windows-SMBServer/Security',
        'Microsoft-Windows-CodeIntegrity/Operational',
        'Microsoft-Windows-AppLocker/EXE and DLL',
        'Microsoft-Windows-AppLocker/MSI and Script',
        'Microsoft-Windows-NTLM/Operational',
        'Microsoft-Windows-Security-Mitigations/KernelMode',
        'Microsoft-Windows-PrintService/Operational',
        'Microsoft-Windows-Diagnostics-Performance/Operational'
    )
    # Son $DaysBack gun icin XPath zaman filtresi (timediff milisaniye cinsinden doner)
    $ms    = [int64]$DaysBack * 86400000
    $xpath = "*[System[TimeCreated[timediff(@SystemTime) <= $ms]]]"
    foreach ($ch in $channels) {
        $safe = ($ch -replace '[\\/ ]','_')
        $dst  = Join-Path $evtxDir "$safe.evtx"
        try {
            # Once zaman filtreli export dene
            & wevtutil epl "$ch" "$dst" "/q:$xpath" /ow:true 2>$null
            if (-not (Test-Path $dst)) {
                # Kanal XPath sorgusunu desteklemiyorsa tum log'u export et
                & wevtutil epl "$ch" "$dst" /ow:true 2>$null
            }
            if (Test-Path $dst) { Add-Manifest $dst }
        } catch {}
    }
    Write-Log "    Ham EVTX export tamamlandi (son $DaysBack gun)." 'OK'
}

Invoke-Module 'Event Loglar (kritik event parse)' {
    $parsedDir = Join-Path (Join-Path $CaseRoot $Dirs.EventLogs) 'Parsed'
    $null = New-Item -ItemType Directory -Path $parsedDir -Force
    $since = (Get-Date).AddDays(-1 * $DaysBack)

    function Export-EventIds {
        param([string]$LogName, [int[]]$Ids, [string]$OutFile)
        try {
            $filter = @{ LogName = $LogName; StartTime = $since }
            if ($Ids) { $filter['Id'] = $Ids }
            $events = Get-WinEvent -FilterHashtable $filter -MaxEvents 100000 -ErrorAction Stop |
                Select-Object TimeCreated, Id, LevelDisplayName, ProviderName,
                    @{N='Message';E={ ($_.Message -replace '\s+',' ') }}
            Save-Csv $events (Join-Path $parsedDir $OutFile)
            Write-Log "    $LogName ($($events.Count) kayit) -> $OutFile" 'OK'
        } catch {
            Write-Log "    $LogName parse atlandi: $($_.Exception.Message)" 'WARN'
        }
    }

    # Security: logon/hesap/yetki/proses/gorev/log temizleme
    Export-EventIds 'Security' @(
        4624,4625,4634,4647,4648,4672,4673,4688,4689,
        4697,4698,4699,4700,4701,4702,4719,4720,4722,4723,4724,4725,4726,
        4728,4732,4756,4738,4740,4767,4768,4769,4771,4776,4798,4799,
        5140,5142,5143,5144,5145,1102
    ) 'security_key_events.csv'

    # System: servis kurulumu, log temizleme, beklenmedik kapanma
    Export-EventIds 'System' @(7045,7034,7035,7036,7040,104,1074,6005,6006,6008,41) 'system_key_events.csv'

    # PowerShell scriptblock logging (4104) — saldirgan komutlari burada
    Export-EventIds 'Microsoft-Windows-PowerShell/Operational' @(4103,4104,4105,4106) 'powershell_operational.csv'

    # WMI activity
    Export-EventIds 'Microsoft-Windows-WMI-Activity/Operational' @(5857,5858,5859,5860,5861) 'wmi_activity.csv'

    # RDP oturumlari
    Export-EventIds 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' @(21,22,23,24,25) 'rdp_local_sessions.csv'

    # Defender tespitleri
    Export-EventIds 'Microsoft-Windows-Windows Defender/Operational' @(1006,1007,1008,1009,1010,1011,1015,1116,1117,5001,5007) 'defender_events.csv'

    # Sysmon (varsa) — tum event'ler cok degerli
    Export-EventIds 'Microsoft-Windows-Sysmon/Operational' @() 'sysmon_all.csv'
}

# ===========================================================================
#  9) REGISTRY HIVE KOPYALARI
# ===========================================================================
if ($CollectRegistryHives) {
    Invoke-Module 'Registry Hive Kopyalari' {
        $regDir = Join-Path $CaseRoot $Dirs.Registry
        # HKLM hive'lari reg save ile (canli sistemde calisir)
        $saves = @{ 'SYSTEM'='HKLM\SYSTEM'; 'SOFTWARE'='HKLM\SOFTWARE'; 'SAM'='HKLM\SAM'; 'SECURITY'='HKLM\SECURITY' }
        foreach ($name in $saves.Keys) {
            $dst = Join-Path $regDir "$name.hiv"
            try {
                & reg save $saves[$name] "$dst" /y 2>$null
                if (Test-Path $dst) { Add-Manifest $dst }
            } catch { Write-Log "    reg save $name basarisiz" 'WARN' }
        }

        # Kullanici NTUSER.DAT / UsrClass.dat
        #   YUKLU kovanlar (oturum acik kullanici) -> reg save HKU\<SID>  (VSS gerekmez, GARANTI)
        #   Yuklu olmayanlar              -> dosyayi VSS/direct kopyala (fallback)
        $loadedSids = @{}
        try {
            Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' } |
                ForEach-Object { $loadedSids[$_.PSChildName] = $true }
        } catch {}
        $sidByPath = @{}
        try {
            Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue |
                Where-Object { $_.SID -and $_.LocalPath } |
                ForEach-Object { $sidByPath[$_.LocalPath] = $_.SID }
        } catch {}

        foreach ($dir in (Get-UserProfileDirs)) {
            $u = $dir.Name
            $sid = $sidByPath[$dir.FullName]
            $ntDst = Join-Path $regDir ("ntuser_{0}.dat" -f $u)
            $ucDst = Join-Path $regDir ("usrclass_{0}.dat" -f $u)

            if ($sid -and $loadedSids[$sid]) {
                try { & reg save "HKU\$sid"         "$ntDst" /y 2>$null; if (Test-Path $ntDst) { Add-Manifest $ntDst } } catch {}
                try { & reg save "HKU\${sid}_Classes" "$ucDst" /y 2>$null; if (Test-Path $ucDst) { Add-Manifest $ucDst } } catch {}
            }
            # reg save olmadiysa / yuklu degilse -> dosya kopyasina dus
            if (-not (Test-Path $ntDst)) { Copy-Artifact (Join-Path $dir.FullName 'NTUSER.DAT') $ntDst -PreferVSS }
            if (-not (Test-Path $ucDst)) { Copy-Artifact (Join-Path $dir.FullName 'AppData\Local\Microsoft\Windows\UsrClass.dat') $ucDst -PreferVSS }
        }
    }
}

# ===========================================================================
# 10) FORENSIC ARTEFAKTLAR (Prefetch, Amcache, SRUM, vb.)
# ===========================================================================
Invoke-Module 'Forensic Artefaktlar' {
    $fDir = Join-Path $CaseRoot $Dirs.Forensic

    # Prefetch (program calistirma kaniti) — admin ile okunur
    Copy-Tree "$env:WINDIR\Prefetch" (Join-Path $fDir 'Prefetch') '*.pf'

    # Amcache.hve (yuklenmis/calismis binary metadata + SHA1) — kilitli, VSS gerek
    Copy-Artifact "$env:WINDIR\AppCompat\Programs\Amcache.hve" (Join-Path $fDir 'Amcache.hve') -PreferVSS
    Copy-Artifact "$env:WINDIR\AppCompat\Programs\RecentFileCache.bcf" (Join-Path $fDir 'RecentFileCache.bcf') -PreferVSS

    # SRUM (System Resource Usage Monitor — ag/uygulama kullanim gecmisi) — kilitli, VSS gerek
    Copy-Artifact "$env:WINDIR\System32\sru\SRUDB.dat" (Join-Path $fDir 'SRUDB.dat') -PreferVSS

    # WBEM repository (WMI persistence DB)
    Copy-Tree "$env:WINDIR\System32\wbem\Repository" (Join-Path $fDir 'WBEM_Repository')

    # Shimcache (AppCompatCache) SYSTEM hive icindedir; -CollectRegistryHives ile gelir.
    # Ayrica registry'den anlik export:
    try {
        & reg export 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' (Join-Path $fDir 'AppCompatCache.reg') /y 2>$null
        $ac = Join-Path $fDir 'AppCompatCache.reg'; if (Test-Path $ac) { Add-Manifest $ac }
    } catch {}

    # USB cihaz gecmisi
    try {
        & reg export 'HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR' (Join-Path $fDir 'USBSTOR.reg') /y 2>$null
        $u = Join-Path $fDir 'USBSTOR.reg'; if (Test-Path $u) { Add-Manifest $u }
    } catch {}

    # $MFT + $UsnJrnl (ham NTFS) — -CollectMFT / -Full ile. Buyuk olabilir; gercek 6/17-6/23
    # penceresinin dosya olusturma/silme/yeniden-adlandirma izlerini tasir.
    if ($CollectMFT) {
        Write-Log "    USN journal aliniyor ($SystemDrive)..." 'INFO'
        Copy-UsnJournal $SystemDrive (Join-Path $fDir 'UsnJrnl.csv') | Out-Null
        Write-Log "    \$MFT aliniyor ($SystemDrive)..." 'INFO'
        if (Copy-MasterFileTable (Join-Path $fDir 'MFT.bin')) {
            Write-Log "    \$MFT toplandi (MFTECmd ile offline parse edilebilir)." 'OK'
        }
    }
}

# ===========================================================================
# 11) FILE SYSTEM ARTEFAKTLARI (Recent, LNK, Jump List, indirilenler)
# ===========================================================================
Invoke-Module 'Dosya Sistemi Artefaktlari' {
    $fsDir = Join-Path $CaseRoot $Dirs.FileSystem

    Get-UserProfileDirs | ForEach-Object {
        $u = $_.Name; $base = $_.FullName
        # Recent + LNK + Jump Lists
        Copy-Tree (Join-Path $base 'AppData\Roaming\Microsoft\Windows\Recent') (Join-Path $fsDir "$u\Recent")
        # Downloads klasorunde sadece listele (kopyalama agir olabilir)
        $dl = Join-Path $base 'Downloads'
        if (Test-Path $dl) {
            Save-Csv (Get-ChildItem $dl -Recurse -File -ErrorAction SilentlyContinue | Select-Object FullName,Length,CreationTime,LastWriteTime) (Join-Path $fsDir "$u`_downloads_listing.csv")
        }
    }

    # Supheli konumlardaki calistirilabilir dosyalar (drop location'lar) — hash'li
    $cutoff = (Get-Date).AddDays(-1 * $DaysBack)
    $dropPaths = @(
        $env:TEMP, "$env:WINDIR\Temp", $env:ProgramData,
        "$env:PUBLIC", "$env:APPDATA", "$env:LOCALAPPDATA"
    ) | Sort-Object -Unique
    $exts = '*.exe','*.dll','*.ps1','*.vbs','*.js','*.bat','*.scr','*.hta','*.jar','*.msi','*.cmd'
    $drops = foreach ($p in $dropPaths) {
        if (Test-Path $p) {
            Get-ChildItem $p -Include $exts -File -Recurse -ErrorAction SilentlyContinue -Depth 3 |
                Where-Object { $_.LastWriteTime -gt $cutoff } |
                ForEach-Object {
                    $h = ''
                    try { $h = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}
                    [pscustomobject]@{ Path=$_.FullName; Size=$_.Length; Created=$_.CreationTime; Modified=$_.LastWriteTime; SHA256=$h }
                }
        }
    }
    Save-Csv $drops (Join-Path $fsDir ("suspicious_executables_last{0}d.csv" -f $DaysBack))

    # Son $DaysBack gunde degisen tum dosyalar (sistem genelinde, sinirli) — timeline icin
    try {
        # Veeam yedek verisi + buyuk gurultu dizinlerini hariç tut (proxy/server'da kritik)
        $excludeRx = '\\Windows\\WinSxS\\|\\Windows\\servicing\\|\\ProgramData\\Veeam\\|\\VeeamFLR\\|\.vbk$|\.vib$|\.vrb$|\.vlb$|\.vsb$|\.vbm$|\.vbackup$'
        $recent = Get-ChildItem "$SystemDrive\" -Recurse -File -ErrorAction SilentlyContinue -Force |
            Where-Object { $_.LastWriteTime -gt $cutoff -and $_.FullName -notmatch $excludeRx } |
            Select-Object FullName, Length, CreationTime, LastWriteTime -First 50000
        Save-Csv $recent (Join-Path $fsDir ("recently_modified_files_last{0}d.csv" -f $DaysBack))
    } catch {}
}

# ===========================================================================
# 12) POWERSHELL & KOMUT GECMISI
# ===========================================================================
Invoke-Module 'PowerShell / Komut Gecmisi' {
    $psDir = Join-Path $CaseRoot $Dirs.PowerShell
    Get-UserProfileDirs | ForEach-Object {
        $hist = Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
        if (Test-Path $hist) { Copy-Artifact $hist (Join-Path $psDir ("psreadline_{0}.txt" -f $_.Name)) }
    }
}

# ===========================================================================
# 13) TARAYICI ARTEFAKTLARI
# ===========================================================================
if ($CollectBrowserArtifacts) {
    Invoke-Module 'Tarayici Artefaktlari' {
        $bDir = Join-Path $CaseRoot $Dirs.Browser
        Get-UserProfileDirs | ForEach-Object {
            $u = $_.Name; $base = $_.FullName
            # Chrome / Edge (Chromium) — History, Cookies, Login Data, Bookmarks
            $chromiumProfiles = @(
                "$base\AppData\Local\Google\Chrome\User Data",
                "$base\AppData\Local\Microsoft\Edge\User Data",
                "$base\AppData\Local\BraveSoftware\Brave-Browser\User Data"
            )
            foreach ($cp in $chromiumProfiles) {
                if (Test-Path $cp) {
                    Get-ChildItem $cp -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(Default|Profile)' } | ForEach-Object {
                        $prof = $_.FullName; $bn = (Split-Path $cp -Parent | Split-Path -Leaf)
                        foreach ($f in 'History','Cookies','Login Data','Web Data','Bookmarks') {
                            $src = Join-Path $prof $f
                            if (Test-Path $src) { Copy-Artifact $src (Join-Path $bDir "$u\$bn\$($_.Name)\$f") -PreferVSS }
                        }
                    }
                }
            }
            # Firefox — places.sqlite, cookies.sqlite, downloads
            $ff = "$base\AppData\Roaming\Mozilla\Firefox\Profiles"
            if (Test-Path $ff) {
                Get-ChildItem $ff -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                    foreach ($f in 'places.sqlite','cookies.sqlite','formhistory.sqlite','downloads.sqlite') {
                        $src = Join-Path $_.FullName $f
                        if (Test-Path $src) { Copy-Artifact $src (Join-Path $bDir "$u\Firefox\$($_.Name)\$f") -PreferVSS }
                    }
                }
            }
        }
    }
}

# ===========================================================================
# 14) DEFENDER / ANTIVIRUS
# ===========================================================================
Invoke-Module 'Windows Defender / AV' {
    $dDir = Join-Path $CaseRoot $Dirs.Defender
    try {
        Save-Json (Get-MpComputerStatus)  (Join-Path $dDir 'mp_computer_status.json')
        Save-Json (Get-MpThreat)          (Join-Path $dDir 'mp_threats.json')
        Save-Json (Get-MpThreatDetection) (Join-Path $dDir 'mp_threat_detections.json')
        # ONEMLI: Saldirganlar AV exclusion ekler — buraya bak!
        Save-Json (Get-MpPreference | Select-Object Exclusion*,DisableRealtimeMonitoring,DisableBehaviorMonitoring,DisableScriptScanning,DisableIOAVProtection,MAPSReporting,SubmitSamplesConsent) (Join-Path $dDir 'mp_preferences_exclusions.json')
    } catch { Write-Log "    Defender cmdlet'leri yok/erisilmez." 'WARN' }

    # Defender tespit gecmisi dosyalari
    Copy-Tree (Join-Path $env:ProgramData 'Microsoft\Windows Defender\Scans\History') (Join-Path $dDir 'Defender_History')
    # Defender Support loglari
    Copy-Tree (Join-Path $env:ProgramData 'Microsoft\Windows Defender\Support') (Join-Path $dDir 'Defender_Support') '*.log'
}

# ===========================================================================
#  KAPANIS: VSS temizle, ozet, paketle
# ===========================================================================
Invoke-Module 'Manifest & Ozet' {
    # Tum CSV/JSON/TXT ciktilarini da manifest'e ekle (ham dosyalar zaten eklendi)
    Get-ChildItem $CaseRoot -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -ne $script:Manifest -and $_.Extension -in '.csv','.json','.txt' } |
        ForEach-Object { Add-Manifest $_.FullName }

    $summary = [ordered]@{
        Host              = $HostName
        CollectionStart   = $Stamp
        CollectionEndUtc  = (Get-Date).ToUniversalTime().ToString('o')
        RunAsAdmin        = $IsAdmin
        VSSUsed           = [bool]$script:VssLink
        Options           = @{
            UseVSS = [bool]$UseVSS; RegistryHives = [bool]$CollectRegistryHives
            Browser = [bool]$CollectBrowserArtifacts; HashRunningBinaries = [bool]$HashRunningBinaries
            DaysBack = $DaysBack
        }
        TotalFiles        = (Get-ChildItem $CaseRoot -Recurse -File -ErrorAction SilentlyContinue).Count
        TotalSize_MB      = [math]::Round(((Get-ChildItem $CaseRoot -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum / 1MB), 2)
    }
    Save-Json $summary (Join-Path $script:MetaDir 'SUMMARY.json')
    Write-Log "Toplam dosya: $($summary.TotalFiles) | Boyut: $($summary.TotalSize_MB) MB" 'OK'
}

Remove-VssSnapshot
try { Stop-Transcript | Out-Null } catch {}

# Paketleme — 7-Zip varsa onu kullan (buyuk/>2GB koleksiyonlar icin), yoksa Compress-Archive
if (-not $NoCompress) {
    Write-Log "Paketleniyor..." 'INFO'
    $sevenZip = $null
    foreach ($cand in @("$env:ProgramFiles\7-Zip\7z.exe", "${env:ProgramFiles(x86)}\7-Zip\7z.exe")) {
        if ($cand -and (Test-Path $cand)) { $sevenZip = $cand; break }
    }
    if (-not $sevenZip) { $c = Get-Command 7z.exe -ErrorAction SilentlyContinue; if ($c) { $sevenZip = $c.Source } }

    $archive = $null
    try {
        if ($sevenZip) {
            $archive = "$CaseRoot.7z"
            & $sevenZip a -t7z -mx=1 -mmt=on -bso0 -bsp0 "$archive" "$CaseRoot" | Out-Null
            if (-not (Test-Path $archive)) { throw '7-Zip arsivi olusmadi' }
            Write-Log "7-Zip ile paketlendi." 'INFO'
        } else {
            $archive = "$CaseRoot.zip"
            Compress-Archive -Path $CaseRoot -DestinationPath $archive -Force -ErrorAction Stop
        }
        $aHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
        Write-Log "PAKET HAZIR: $archive" 'OK'
        Write-Log "ARSIV SHA256: $aHash" 'OK'
        "$archive`nSHA256: $aHash" | Out-File -FilePath "$CaseRoot`_ARCHIVE_SHA256.txt" -Encoding UTF8
    } catch {
        Write-Log "Paketleme basarisiz (klasoru manuel sikistirin): $($_.Exception.Message)" 'WARN'
        if (-not $sevenZip) { Write-Log "Ipucu: 7-Zip kurulu olsaydi >2GB koleksiyon otomatik paketlenirdi." 'WARN' }
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " TOPLAMA TAMAMLANDI" -ForegroundColor Cyan
Write-Host " Cikti klasoru : $CaseRoot" -ForegroundColor Cyan
if (-not $NoCompress) { Write-Host " Arsiv         : $CaseRoot (.7z veya .zip)" -ForegroundColor Cyan }
Write-Host " Manifest      : $script:Manifest" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
