# MagiciansReveal V3

`Minecraft-SS-Forensics.ps1` is a defensive, read-only Minecraft forensic scanner for authorized server staff. It analyzes local Minecraft data, mods, manifests, logs, JVM arguments, processes, Windows artifacts, suspicious strings, URLs, signatures, and timelines.

## One-line run from GitHub

Open **Windows PowerShell** and run this exact command:

```powershell
powershell.exe -ExecutionPolicy Bypass -Command "Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/timzz71/MagiciansReveal-V3/main/Minecraft-SS-Forensics.ps1')"
```

Use the plain raw URL shown above. Do not paste the GitHub Markdown form:

```text
[https://...](https://...)
```

The script will request its authorization confirmation interactively before scanning.

## Recommended local method

Download the script first so it can be reviewed and retained with the incident record:

```powershell
$url = 'https://raw.githubusercontent.com/timzz71/MagiciansReveal-V3/main/Minecraft-SS-Forensics.ps1'
$file = Join-Path $PWD 'Minecraft-SS-Forensics.ps1'
Invoke-WebRequest -Uri $url -OutFile $file
Get-Content -LiteralPath $file -TotalCount 30
powershell.exe -ExecutionPolicy Bypass -File $file
```

## Parameters

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Minecraft-SS-Forensics.ps1 `
  -InstancePath 'C:\Users\Player\AppData\Roaming\.minecraft' `
  -OutputPath '.\Forensics-Report' `
  -EvidencePath 'D:\Case-Evidence' `
  -Offline -DeepScan -HashFiles
```

Available switches include `-InstancePath`, `-OutputPath`, `-EvidencePath`, `-Offline`, `-DeepScan`, `-HashFiles`, and `-Help`.

## Output

The selected output directory contains:

- `forensics-report.html`
- `forensics-report.json`
- `forensics-findings.csv`
- `forensics-timeline.csv`
- `forensics-hashes.csv`
- `forensics-summary.txt`

## Safety and limitations

The scanner is offline-only. It does not visit, resolve, ping, download from, or upload to extracted domains. It does not execute evidence, modify or delete files, quarantine items, terminate processes, disable software, or punish players. Findings are indicators requiring review and are not proof of cheating. Some protected Windows evidence sources may be unavailable without Administrator access and are reported as unsupported rather than treated as clean.

Use this tool only on systems and evidence for which you have explicit authorization. Preserve the original outputs and record the collection time, operator, host, and case identifier.

## License

Use and distribute according to the license and authorization policy included with your repository.
