[CmdletBinding(SupportsShouldProcess = $false)]
param(
    [string]$InstancePath,
    [string]$OutputPath = (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Minecraft-SS-Forensics-Output'),
    [string]$EvidencePath,
    [switch]$Offline = $true,
    [switch]$DeepScan,
    [switch]$HashFiles,
    [switch]$Quiet,
    [switch]$SelfTest,
    [switch]$Help,
    [string]$ConfigPath,
    [switch]$Authorized
)

<#
.SYNOPSIS
    Read-only Minecraft anti-cheat forensic scanner for authorized server staff.
.DESCRIPTION
    Collects local Minecraft, launcher, process, file, signature, timeline, archive,
    string, URL, and Windows-evidence metadata. It never contacts extracted domains,
    executes payloads, modifies evidence, deletes files, or assigns guilt. Every
    finding requires analyst review. The indicator/configuration tables below are
    intentionally editable and are used only for offline comparison.
.PARAMETER InstancePath
    Optional Minecraft/launcher root. If omitted, common local locations are searched.
.PARAMETER OutputPath
    Directory receiving the six deterministic report files.
.PARAMETER EvidencePath
    Additional read-only evidence root to inspect.
.PARAMETER Offline
    Kept for explicitness; this script is offline-only and never performs network I/O.
.PARAMETER DeepScan
    Scans more text and archive/class content within configured limits.
.PARAMETER HashFiles
    Adds SHA-256 hashes for relevant files.
.PARAMETER ConfigPath
    Optional analyst-maintained JSON configuration merged with embedded defaults.
.PARAMETER Authorized
    Required explicit authorization confirmation.
.PARAMETER SelfTest
    Creates harmless temporary fixtures, scans them, verifies output schemas, then removes fixtures.
.EXAMPLE
    .\Minecraft-SS-Forensics.ps1 -Authorized -OutputPath 'D:\Cases\MC-001' -HashFiles -DeepScan
.EXAMPLE
    .\Minecraft-SS-Forensics.ps1 -SelfTest -Authorized
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ========================= Editable offline configuration =========================
$Config = [ordered]@{
    CheatClients = @{
        'LiquidBounce'=@('liquidbounce','liquid-bounce','liquid_bounce','lbnextgen'); 'LiquidBounce Nextgen'=@('liquidbounce nextgen','liquidbounce-nextgen','liquidbounce_nextgen','lbng')
        'Wurst'=@('wurst','wurstclient'); 'Meteor'=@('meteor','meteorclient'); 'BleachHack'=@('bleachhack','bleach-hack','bleach_hack')
        'Impact'=@('impact','impactclient'); 'Inertia'=@('inertia'); 'Aristois'=@('aristois'); 'Vape'=@('vape','v4pe'); 'Future'=@('futureclient','future')
        'RusherHack'=@('rusherhack','rusher-hack'); 'Pyro'=@('pyroclient'); 'Boze'=@('boze'); 'Kami Blue'=@('kami blue','kami-blue','kami_blue','kamiblue')
        'ThunderHack'=@('thunderhack','thunder-hack'); 'Raven'=@('ravenclient','raven'); 'Raven B+'=@('raven b+','raven-b+','ravenbplus','ravenb')
        'Rise'=@('riseclient','rise'); 'Exhibition'=@('exhibition'); 'Sigma'=@('sigmaclient','sigma'); 'Wolfram'=@('wolfram'); 'FDP Client'=@('fdpclient','fdp-client','fdp_client')
        'Tenacity'=@('tenacity'); 'Dortware'=@('dortware'); 'Astolfo'=@('astolfo'); 'Moon'=@('moonclient'); 'Novo'=@('novoclient'); 'Zeroday'=@('zeroday','zero-day')
        'Whiteout'=@('whiteout'); 'Baritone'=@('baritone')
    }
    Modules = @('KillAura','AimAssist','TriggerBot','AutoClicker','Reach','Velocity','AntiKnockback','Fly','Speed','Bhop','Strafe','Scaffold','Tower','Step','LongJump','Jesus','NoFall','Phase','Blink','Timer','Freecam','XRay','ESP','Tracers','StorageESP','FullBright','ChestStealer','InventoryMove','AutoArmor','AutoTotem','FastPlace','FastBreak','Nuker','Rotation','Criticals','Disabler','PacketFly','NoSlow','SafeWalk','Backtrack','LegitAssist','Hitboxes','AutoCrystal','CrystalAura','Surround','SelfTrap','AnchorAura','BedAura','AutoMace','ShieldBreaker')
    WeakModules = @('ESP','Speed','FullBright','Hitboxes')
    PackageClassPatterns = @('(?i)liquidbounce|wurstclient|meteorclient|bleachhack|rusherhack|thunderhack|baritone','(?i)(?:killaura|aimassist|triggerbot|autoclicker|packetfly|crystalaura|shieldbreaker)')
    DomainPatterns = @('(?i)(?:discord(?:app)?\.com/api/webhooks|discord\.gg|pastebin\.com|hastebin\.com|raw\.githubusercontent\.com|tinyurl\.com|bit\.ly|t\.co|ngrok\.io|duckdns\.org|no-ip\.com)')
    FileNamePatterns = @('(?i)(?:inject|loader|agent|cheat|client|clicker|killaura|autoclick|rusher|liquid|meteor|wurst|vape|baritone)')
    KnownLegitimateMods = @('fabric-api','fabricloader','cloth-config','modmenu','sodium','lithium','phosphor','ferritecore','journeymap','xaeros')
    AllowedDomains = @('minecraft.net','mojang.com','fabricmc.net','files.minecraftforge.net','modrinth.com','curseforge.com','github.com')
    AllowedPaths = @()
    ScanExclusions = @('node_modules','.git','Windows\WinSxS')
    MaxFileBytes = 50MB; MaxArchiveBytes = 200MB; MaxTextBytes = 10MB; MaxFiles = 100000; TimeoutSeconds = 30
    SeverityWeights = @{ Client=45; Module=12; Injection=55; Obfuscation=15; Domain=20; Timeline=10; Native=35; SelfDestruct=35 }
    RegexRules = @('(?i)-javaagent(?::|=)|-agentpath(?::|=)|-Xbootclasspath','(?i)premain|agentmain|Instrumentation|URLClassLoader|defineClass|System\.load(?:Library)?','(?i)base64|xor\s*\(|aes|decrypt|string\s*decoder|reflection|ClassLoader|Mixin.*transform','(?i)(self[-_ ]?delete|cleanup|wipe|uninstall|destroy|suicide|remove).*\.(jar|dll|exe|ps1|bat|cmd|vbs)?')
}
$OutputNames = @('forensics-report.html','forensics-report.json','forensics-findings.csv','forensics-timeline.csv','forensics-hashes.csv','forensics-summary.txt')
$script:ToolName = 'MagiciansReveal V3'
$script:Unsupported = [System.Collections.Generic.List[object]]::new()
$script:Allowlisted = [System.Collections.Generic.List[object]]::new()
$script:Mods = [System.Collections.Generic.List[object]]::new()

<# The following helpers deliberately use only local .NET/PowerShell APIs. They do
not invoke a shell, load assemblies from evidence, open URLs, or resolve names. #>
function Add-Unsupported([string]$Source,[string]$Reason) { $script:Unsupported.Add([pscustomobject]@{Source=$Source;Reason=$Reason}) }
function Test-AllowedPath([string]$Path) { foreach($p in $Config.AllowedPaths){try{if((Normalize $Path).StartsWith((Normalize $p),[StringComparison]::OrdinalIgnoreCase)){return $true}}catch{}}; return $false }
function Test-AllowedDomain([string]$Domain) { foreach($d in $Config.AllowedDomains){if($Domain -eq $d -or $Domain.EndsWith('.'+$d)){return $true}}; return $false }
function Get-SignatureRecord([string]$Path) {
    try { $s=Get-AuthenticodeSignature -LiteralPath $Path; return [pscustomobject]@{Status=[string]$s.Status;Signer=if($s.SignerCertificate){$s.SignerCertificate.Subject}else{''};Issuer=if($s.SignerCertificate){$s.SignerCertificate.Issuer}else{''};CertificateNotAfter=if($s.SignerCertificate){$s.SignerCertificate.NotAfter.ToUniversalTime().ToString('o')}else{''}} } catch { return [pscustomobject]@{Status='Unavailable';Signer='';Issuer='';CertificateNotAfter=''} }
}
function Get-ArchiveManifest([string]$Path) {
    try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop; $z=[IO.Compression.ZipFile]::OpenRead($Path); try { foreach($e in $z.Entries){if($e.FullName -match '(?i)(fabric.mod.json|quilt.mod.json|mods.toml|neoforge.mods.toml|mcmod.info|MANIFEST.MF|\.class$)'){ $ms=$e.Open(); $sr=[IO.StreamReader]::new($ms); try{$text=$sr.ReadToEnd()}finally{$sr.Dispose();$ms.Dispose()}; Add-TextFindings $text "$Path::$($e.FullName)" 'archive manifest/class' (if($HashFiles){Get-Sha256 $Path}else{''}) '' } } } finally{$z.Dispose()} } catch { Add-Error $_.Exception.Message $Path }
}
function Add-ModInventory([IO.FileInfo]$File) {
    $manifest=''; try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop; $z=[IO.Compression.ZipFile]::OpenRead($File.FullName); try { $entry=$z.Entries|Where-Object {$_.FullName -match '(?i)(fabric.mod.json|quilt.mod.json|mods.toml|neoforge.mods.toml|mcmod.info)$'}|Select-Object -First 1; if($entry){$sr=[IO.StreamReader]::new($entry.Open());try{$manifest=$sr.ReadToEnd()}finally{$sr.Dispose()}} }finally{$z.Dispose()} }catch{Add-Error $_.Exception.Message $File.FullName}; $script:Mods.Add([pscustomobject][ordered]@{Path=$File.FullName;Name=$File.BaseName;ManifestPreview=if($manifest.Length -gt 1000){$manifest.Substring(0,1000)}else{$manifest};SHA256=if($HashFiles){Get-Sha256 $File.FullName}else{''};ModifiedUtc=$File.LastWriteTimeUtc.ToString('o')}); if($manifest){Add-TextFindings $manifest $File.FullName 'mod manifest' '' $File.LastWriteTimeUtc.ToString('o')}; Get-ArchiveManifest $File
}
function Scan-WindowsEvidence {
    $sources=@(@{N='Recycle Bin';P=(Join-Path $env:SystemDrive '$Recycle.Bin')},@{N='Prefetch';P=(Join-Path $env:SystemRoot 'Prefetch')},@{N='Jump Lists';P=(Join-Path $env:APPDATA 'Microsoft\Windows\Recent\AutomaticDestinations')},@{N='Recent files';P=(Join-Path $env:APPDATA 'Microsoft\Windows\Recent')},@{N='RecentFileCache';P=(Join-Path $env:SystemRoot 'AppCompat\Programs')})
    foreach($s in $sources){if(Test-Path -LiteralPath $s.P){try{Get-ChildItem -LiteralPath $s.P -File -Force -ErrorAction Stop|Where-Object{$_.Name -match '(?i)java|minecraft|\.jar|launcher|cheat|client'}|ForEach-Object{ $script:Timeline += [pscustomobject][ordered]@{TimestampUtc=$_.LastWriteTimeUtc.ToString('o');Event='Windows evidence reference';Path=$_.FullName;Source=$s.N;Details=$_.Name} }}catch{Add-Error $_.Exception.Message $s.P}}else{Add-Unsupported $s.N 'Source absent or inaccessible'} }
    Add-Unsupported 'Amcache/Shimcache/USN/Search index' 'Not collected when protected, unavailable, or requiring specialized forensic parsers; no failure is inferred.'
}
function Scan-ProcessRelationships {
    try { $ps=@(Get-CimInstance Win32_Process -ErrorAction Stop); foreach($p in $ps|Where-Object{$_.Name -match '(?i)java|minecraft|launcher'}){ $cmd=[string]$p.CommandLine; $path=[string]$p.ExecutablePath; $hash=''; Add-TextFindings "$path`n$cmd" $path 'process/JVM metadata' $hash ''; if($cmd -match '(?i)-javaagent|-agentpath|-Xbootclasspath|premain|agentmain'){ $script:Findings += New-Finding 'Injection' 'High' 82 'process command line' $path $Matches[0] 'JVM external-agent argument' $hash '' 'Legitimate profilers and security agents exist.' 'Obtain launch provenance and correlate with an on-disk agent, hash, and independent log evidence.' 'corroborated' }; if($path -match '(?i)\\(Temp|Downloads|AppData)\\|^[A-Z]:\\$'){ $script:Findings += New-Finding 'UnusualLaunchPath' 'Medium' 60 'process metadata' $path $path 'Java/Minecraft process launched from unusual location' $hash '' 'Portable launchers and custom installations are common.' 'Confirm installation provenance, parent process, signature, and timeline.' 'weak' }; try{$parent=$ps|Where-Object{$_.ProcessId -eq $p.ParentProcessId}|Select-Object -First 1;if($parent){$script:Timeline += [pscustomobject][ordered]@{TimestampUtc='';Event='Process relationship';Path=$path;Source='Win32_Process';Details="$($p.Name) parent $($parent.Name) [$($parent.ProcessId)]"}}}catch{}} } catch {Add-Unsupported 'Process inspection' $_.Exception.Message} }
function Scan-File([IO.FileInfo]$File) {
    $hash=if($HashFiles){Get-Sha256 $File.FullName}else{''}; $sig=if($File.Extension -match '(?i)\.dll|\.exe|\.sys'){Get-SignatureRecord $File.FullName}else{[pscustomobject]@{Status='NotApplicable';Signer='';Issuer='';CertificateNotAfter=''}}; $owner=''; if($HashFiles -and $File.Length -lt 5MB){try{$owner=(Get-Acl -LiteralPath $File.FullName -ErrorAction Stop).Owner}catch{}}; $script:Hashes += [pscustomobject][ordered]@{Path=$File.FullName;Name=$File.Name;Length=$File.Length;CreationTimeUtc=$File.CreationTimeUtc;LastWriteTimeUtc=$File.LastWriteTimeUtc;LastAccessTimeUtc=$File.LastAccessTimeUtc;Owner=$owner;Attributes=[string]$File.Attributes;SHA256=$hash;SignatureStatus=$sig.Status;Signer=$sig.Signer;Issuer=$sig.Issuer;CertificateNotAfter=$sig.CertificateNotAfter}; $t=$File.LastWriteTimeUtc.ToString('o'); $script:Timeline += [pscustomobject][ordered]@{TimestampUtc=$t;Event='File observed';Path=$File.FullName;Source='filesystem';Details=('Size '+$File.Length)}
    if($File.Name -match '(?i)\.jar$' -and ($File.DirectoryName -match '(?i)mods|resourcepacks|shaderpacks' -or $DeepScan)){Add-ModInventory $File}; if($File.Name -match ($Config.FileNamePatterns -join '|')){$script:Findings += New-Finding 'FileIndicator' 'Low' 35 'filesystem' $File.FullName $File.Name 'editable filename pattern' $hash $t 'Generic names occur in legitimate tooling.' 'Verify origin, signature, manifest, and related evidence.' 'weak'}; if($File.Extension -match '(?i)\.dll|\.exe|\.sys' -and $sig.Status -notin @('Valid','NotApplicable')){$script:Findings += New-Finding 'NativeModule' 'Medium' 58 'Authenticode' $File.FullName $sig.Status 'unsigned or invalid native signature' $hash $t 'Unsigned software can be legitimate.' 'Check publisher, acquisition source, PE metadata, and process loading evidence.' 'weak'}
    if($DeepScan -or $File.Extension -match '(?i)\.(json|toml|yaml|yml|cfg|ini|txt|xml|log|properties|args|bat|cmd|ps1|vbs|jar|class)$'){Add-TextFindings (Read-Text $File.FullName) $File.FullName 'file content' $hash $t}
    if($File.CreationTimeUtc -gt $File.LastWriteTimeUtc.AddMinutes(2) -or $File.LastAccessTimeUtc -lt $File.CreationTimeUtc){$script:Findings += New-Finding 'TimelineAnomaly' 'Informational' 30 'filesystem metadata' $File.FullName 'timestamp ordering' 'timestamp inconsistency; not proof of tampering' $hash $t 'Copying, extraction, clocks, and filesystem behavior explain this.' 'Compare against event logs, archive timestamps, and known installation events.' 'weak'}
}

function Show-Usage { Get-Help -Name $MyInvocation.ScriptName -Full }
function Write-Banner {
    # Do not clear redirected/non-interactive consoles; this keeps self-tests and logging stable.
    Write-Host '====================================================================' -ForegroundColor DarkYellow
    Write-Host '                         MAGICIANSREVEAL V3                         ' -ForegroundColor Yellow
    Write-Host '             Read-only Minecraft forensic scanner                   ' -ForegroundColor White
    Write-Host '====================================================================' -ForegroundColor DarkYellow
    Write-Host ''
}
function Write-FindingsToConsole {
    Write-Host ''; Write-Host 'COMPACT FINDINGS SUMMARY' -ForegroundColor Cyan
    Write-Host '--------------------------------------------------------------------' -ForegroundColor DarkGray
    if($Findings.Count -eq 0){Write-Host '  No indicators were detected by the configured rules.' -ForegroundColor Green;return}
    $groups=@($Findings | Group-Object Severity | Sort-Object @{Expression={switch($_.Name){'Critical'{0}'High'{1}'Medium'{2}'Low'{3}default{4}}}})
    foreach($g in $groups){$c=switch($g.Name){'Critical'{'Red'}'High'{'Magenta'}'Medium'{'Yellow'}'Low'{'DarkYellow'}default{'Gray'}}; Write-Host ('  {0}: {1}' -f $g.Name,$g.Count) -ForegroundColor $c}
    Write-Host ''
    foreach($f in ($Findings | Sort-Object @{Expression={switch($_.Severity){'Critical'{0}'High'{1}'Medium'{2}'Low'{3}default{4}}}},Category,IndicatorMatched,AbsolutePath)){
        $c=switch($f.Severity){'Critical'{'Red'}'High'{'Magenta'}'Medium'{'Yellow'}'Low'{'DarkYellow'}default{'Gray'}}; $path=if($f.AbsolutePath){Split-Path -Leaf $f.AbsolutePath}else{''}; Write-Host ('[{0}] {1} | {2} | {3}% | {4} | {5}' -f $f.Severity,$f.Category,$f.IndicatorMatched,$f.Confidence,$f.EvidenceAssessment,$path) -ForegroundColor $c
    }
    Write-Host ''; Write-Host 'Full paths, explanations, verification guidance, and hashes are in the exported reports.' -ForegroundColor DarkGray
}
function Confirm-Authorization {
    if($Authorized){return $true}; $answer=Read-Host 'This is an authorized server-staff investigation. Type AUTHORIZED to continue'; return ($answer -ceq 'AUTHORIZED')
}
function Show-RunningMinecraft {
    try{$p=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object{$_.Name -match '(?i)^(java|javaw|minecraft|launcher).*\.exe$'});if($p.Count){foreach($x in $p){$started='unknown';try{$started=$x.CreationDate}catch{};Write-Host ('Minecraft process found: PID {0} ({1})' -f $x.ProcessId,$started) -ForegroundColor Green}}else{Write-Host 'No running Minecraft process was detected.' -ForegroundColor DarkGray}}catch{Add-Unsupported 'Running-process inspection' $_.Exception.Message}
}
function Add-Error([string]$Message,[string]$Path='') { $script:Errors += [pscustomobject]@{Message=$Message;Path=$Path} }
function Normalize([string]$Path) { try { if ($Path) { return [IO.Path]::GetFullPath($Path) } } catch {} ; return $Path }
function New-Finding([string]$Category,[string]$Severity,[int]$Confidence,[string]$Source,[string]$Path,[string]$Indicator,[string]$Rule,[string]$Hash,[string]$Timeline,[string]$Explanation,[string]$Verify,[string]$Evidence='weak') {
    $script:FindingNumber++; [pscustomobject][ordered]@{ FindingId=('F-{0:D6}' -f $script:FindingNumber); Category=$Category; Severity=$Severity; Confidence=$Confidence; EvidenceSource=$Source; AbsolutePath=(Normalize $Path); IndicatorMatched=$Indicator; MatchingRule=$Rule; SHA256=$Hash; Timeline=$Timeline; LegitimateExplanations=$Explanation; RecommendedAnalystVerification=$Verify; EvidenceAssessment=$Evidence }
}
function Get-Sha256([string]$Path) { try { if ((Get-Item -LiteralPath $Path).Length -le $Config.MaxFileBytes) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash } } catch { Add-Error $_.Exception.Message $Path }; return '' }
function Get-FileRecord([IO.FileInfo]$File,[string]$Hash='') {
    $owner=''; try {$owner=(Get-Acl -LiteralPath $File.FullName).Owner} catch {}
    $ads=@(); try {$ads=@(Get-Item -LiteralPath $File.FullName -Stream * -ErrorAction Stop | ForEach-Object Stream)} catch {}
    [pscustomobject][ordered]@{Path=$File.FullName;Name=$File.Name;Length=$File.Length;CreationTimeUtc=$File.CreationTimeUtc;LastWriteTimeUtc=$File.LastWriteTimeUtc;LastAccessTimeUtc=$File.LastAccessTimeUtc;Owner=$owner;Attributes=[string]$File.Attributes;AlternateDataStreams=($ads -join ';');SHA256=$Hash}
}
function Read-Text([string]$Path) { try { $f=Get-Item -LiteralPath $Path; if($f.Length -le $Config.MaxTextBytes){return [IO.File]::ReadAllText($Path,[Text.Encoding]::UTF8)} } catch { Add-Error $_.Exception.Message $Path }; return '' }
function Add-TextFindings([string]$Text,[string]$Path,[string]$Source,[string]$Hash,[string]$Timeline) {
    if(!$Text){return}; $norm=($Text.ToLowerInvariant() -replace '[\s_\-\.]','')
    foreach($client in $Config.CheatClients.Keys){ foreach($alias in $Config.CheatClients[$client]) { if($norm.Contains(($alias.ToLowerInvariant()-replace '[\s_\-\.]',''))){$script:Findings += New-Finding 'CheatClient' 'High' 78 $Source $Path $client 'normalized local indicator' $Hash $Timeline 'Legitimate mod forks or references can contain this name.' 'Compare manifest, version, author, signatures, and independent process/timeline evidence.' 'corroborated' } } }
    foreach($module in $Config.Modules){ $rx='(?i)(?<![A-Za-z0-9])'+[regex]::Escape($module)+'(?![A-Za-z0-9])'; if([regex]::IsMatch($Text,$rx)){ $sev=if($Config.WeakModules -contains $module){'Low'}else{'Medium'}; $script:Findings += New-Finding 'ModuleIndicator' $sev 45 $Source $Path $module 'case-insensitive token match' $Hash $Timeline 'The term may be legitimate UI/mod terminology.' 'Inspect surrounding context and seek a second independent source.' 'weak' } }
    foreach($rx in $Config.RegexRules){ if([regex]::IsMatch($Text,$rx)){ $script:Findings += New-Finding 'InjectionOrObfuscation' 'Medium' 55 $Source $Path $rx 'offline regex rule' $Hash $Timeline 'Developer tools and launchers can legitimately use these APIs.' 'Review exact surrounding code/arguments; do not execute the artifact.' 'weak' } }
    foreach($rx in $Config.DomainPatterns){ foreach($m in [regex]::Matches($Text,$rx)){ $script:Findings += New-Finding 'DomainOrURL' 'Low' 50 $Source $Path $m.Value 'offline domain pattern; never resolved' $Hash $Timeline 'Telemetry, documentation, or mod services may be benign.' 'Compare only with local allowlist and case context.' 'weak' } }
}
function Scan-File([IO.FileInfo]$File) {
    $hash=if($HashFiles){Get-Sha256 $File.FullName}else{''}; $script:Hashes += Get-FileRecord $File $hash
    $t=$File.LastWriteTimeUtc.ToString('o'); $script:Timeline += [pscustomobject][ordered]@{TimestampUtc=$t;Event='File observed';Path=$File.FullName;Source='filesystem';Details=('Size '+$File.Length)}
    if($File.Name -match ($Config.FileNamePatterns -join '|')){$script:Findings += New-Finding 'FileIndicator' 'Low' 35 'filesystem' $File.FullName $File.Name 'editable filename pattern' $hash $t 'Generic names occur in legitimate tooling.' 'Verify origin, signature, manifest, and related evidence.' 'weak'}
    if($DeepScan -or $File.Extension -match '(?i)\.((json|toml|yaml|yml|cfg|ini|txt|xml|log|properties|args|bat|cmd|ps1|vbs|jar|class))$'){ Add-TextFindings (Read-Text $File.FullName) $File.FullName 'file content' $hash $t }
}
function Get-Roots { $r=@(); if($InstancePath){$r+=(Normalize $InstancePath)}; if($EvidencePath){$r+=(Normalize $EvidencePath)}; if(!$script:SelfTestMode){$r += @((Join-Path $env:APPDATA '.minecraft'),(Join-Path $env:APPDATA '.fabric'),(Join-Path $env:APPDATA 'Modrinth'),(Join-Path $env:APPDATA 'PrismLauncher'),(Join-Path $env:APPDATA 'CurseForge'),(Join-Path $env:APPDATA 'MultiMC'),(Join-Path $env:APPDATA 'ATLauncher'))}; return @($r | Where-Object {$_ -and (Test-Path -LiteralPath $_ -PathType Container)} | Select-Object -Unique) }
function Test-RelevantFile([IO.FileInfo]$File) {
    $d=$File.FullName.ToLowerInvariant();
    if($d -match '(\\|/)(mods|config|logs|crash-reports|resourcepacks|shaderpacks|versions|libraries|assets|launcher_profiles|instances)(\\|/)'){return $true}
    if($File.Extension -match '(?i)^\.(jar|class|json|toml|yaml|yml|cfg|ini|log|txt|xml|properties|args|dll|exe|sys|ps1|bat|cmd|vbs)$'){return $true}
    return $false
}
function Scan-Files([string[]]$Roots) {
    $count=0; $started=Get-Date; $deadline=$started.AddSeconds(240)
    foreach($root in $Roots){
        if((Get-Date) -gt $deadline){Add-Error 'Four-minute scan budget reached; remaining files were skipped.' $root;break}
        try {
            Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                if((Get-Date) -gt $deadline){return}; if($count -ge $Config.MaxFiles){return}; if(!(Test-RelevantFile $_)){return}
                $count++; if(!$Quiet){Write-Progress -Activity 'Minecraft forensic scan' -Status ("{0} files | {1}" -f $count,$_.FullName) -PercentComplete ([math]::Min(99,(($count/$Config.MaxFiles)*100)))}
                try{Scan-File $_}catch{Add-Error $_.Exception.Message $_.FullName}
            }
        } catch {Add-Error $_.Exception.Message $root}
    }
    if(!$Quiet){Write-Progress -Activity 'Minecraft forensic scan' -Completed -Status ("Completed $count relevant files")}
}
function Scan-Processes { try { Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {$_.Name -match '(?i)java|minecraft|launcher'} | ForEach-Object { $p=$_.ExecutablePath; $cmd=$_.CommandLine; $safePath=''; if($null -ne $p){$safePath=[string]$p}; Add-TextFindings "$p`n$cmd" $safePath 'process metadata' '' '' } } catch {Add-Error $_.Exception.Message 'Win32_Process'} }
function Export-Reports([string[]]$Roots) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null; $utc=(Get-Date).ToUniversalTime().ToString('o'); $counts=@{}; foreach($f in $Findings){$old=0; if($counts.ContainsKey($f.Severity)){$old=[int]$counts[$f.Severity]}; $counts[$f.Severity]=1+$old}
    $report=[ordered]@{SchemaVersion='1.0';CollectionTimeUtc=$utc;OfflineOnly=$true;Authorized=$true;Host=$env:COMPUTERNAME;User=$env:USERNAME;PowerShell=$PSVersionTable.PSVersion.ToString();Windows=(Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption;Roots=$Roots;Summary=[ordered]@{FindingCount=$Findings.Count;SeverityCounts=$counts};Findings=$Findings;Timeline=$Timeline;Hashes=$Hashes;Errors=$Errors;UnsupportedEvidence=@('Recycle Bin content semantics','Amcache/Shimcache/RecentFileCache may require protected registry/artifact access','Windows Search index and USN Journal are reported only when readable')}
    [IO.File]::WriteAllText((Join-Path $OutputPath 'forensics-report.json'),($report|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false)); $Findings|Export-Csv (Join-Path $OutputPath 'forensics-findings.csv') -NoTypeInformation -Encoding utf8; $Timeline|Export-Csv (Join-Path $OutputPath 'forensics-timeline.csv') -NoTypeInformation -Encoding utf8; $Hashes|Export-Csv (Join-Path $OutputPath 'forensics-hashes.csv') -NoTypeInformation -Encoding utf8
    $summary="Minecraft SS Forensics`r`nCollected UTC: $utc`r`nRoots: $($Roots -join '; ')`r`nFindings: $($Findings.Count)`r`nDisclaimer: findings are indicators only and require analyst review; no automatic accusation or punishment was performed.`r`n"; [IO.File]::WriteAllText((Join-Path $OutputPath 'forensics-summary.txt'),$summary,[Text.UTF8Encoding]::new($false))
    $html='<html><head><meta charset="utf-8"><title>Minecraft SS Forensics</title><style>body{font-family:Segoe UI;margin:2em}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:4px}th{background:#eee}.Critical,.High{background:#fdd}</style></head><body><h1>Minecraft SS Forensics</h1><p><b>Disclaimer:</b> Indicators require analyst review. This report is read-only and offline.</p><h2>Executive summary</h2><p>Collected UTC: '+$utc+'; findings: '+$Findings.Count+'</p><h2>Findings</h2><table><tr><th>ID</th><th>Severity</th><th>Category</th><th>Confidence</th><th>Path</th><th>Indicator</th><th>Assessment</th></tr>' + (($Findings|ForEach-Object {'<tr class="'+$_.Severity+'"><td>'+[Web.HttpUtility]::HtmlEncode($_.FindingId)+'</td><td>'+ $_.Severity+'</td><td>'+ $_.Category+'</td><td>'+ $_.Confidence+'</td><td>'+[Web.HttpUtility]::HtmlEncode($_.AbsolutePath)+'</td><td>'+[Web.HttpUtility]::HtmlEncode($_.IndicatorMatched)+'</td><td>'+ $_.EvidenceAssessment+'</td></tr>'}) -join '')+'</table><h2>Errors and skipped evidence</h2><pre>'+[Web.HttpUtility]::HtmlEncode(($Errors|ConvertTo-Json -Depth 5))+'</pre></body></html>'; [IO.File]::WriteAllText((Join-Path $OutputPath 'forensics-report.html'),$html,[Text.UTF8Encoding]::new($false))
}

$script:Findings=@(); $script:Timeline=@(); $script:Hashes=@(); $script:Errors=@(); $script:FindingNumber=0; $script:SelfTestMode=[bool]$SelfTest
if($Help){Show-Usage; exit 0}; Write-Banner; if(!(Confirm-Authorization)){Write-Error 'Authorization confirmation was not provided.'; exit 2}; Show-RunningMinecraft
if($ConfigPath){try{$external=Get-Content -LiteralPath $ConfigPath -Raw|ConvertFrom-Json; foreach($p in $external.PSObject.Properties){$Config[$p.Name]=$p.Value}}catch{Add-Error $_.Exception.Message $ConfigPath}}
if($SelfTest){$tmp=Join-Path ([IO.Path]::GetTempPath()) ('MCSS-'+[guid]::NewGuid()); New-Item -ItemType Directory -Path (Join-Path $tmp 'mods') -Force|Out-Null; [IO.File]::WriteAllText((Join-Path $tmp 'mods\fixture.txt'),'example LiquidBounce and KillAura -javaagent'); $InstancePath=$tmp; try{ $roots=Get-Roots; Scan-Files $roots; if(!$Findings){throw 'Self-test fixture was not detected'}; Export-Reports $roots; Write-Output 'Self-test passed.' } finally {Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue}; exit 0}
if(!$InstancePath -and !$EvidencePath){$asked=Read-Host 'Enter the path to your Minecraft mods folder (Enter uses the default .minecraft\mods)'; if($asked){$InstancePath=(Split-Path -Parent (Normalize $asked))}else{$InstancePath=(Join-Path $env:APPDATA '.minecraft')}}
Write-Host 'Starting forensic scan...' -ForegroundColor Cyan; $roots=Get-Roots; if(!$roots){Add-Error 'No configured Minecraft or evidence roots were accessible.'}; Scan-Files $roots; Scan-ProcessRelationships
$artifactAnswer=Read-Host 'Do you want to scan system artifacts (Prefetch, Recycle Bin, Jump Lists, and recent files)? (y/n)'; if($artifactAnswer -match '^(y|yes)$'){Scan-WindowsEvidence}else{Add-Unsupported 'System artifacts' 'Skipped by operator choice'}
Write-FindingsToConsole; Export-Reports $roots; Write-Host ''; Write-Host "Scan complete. Reports saved to: $(Normalize $OutputPath)" -ForegroundColor Green
