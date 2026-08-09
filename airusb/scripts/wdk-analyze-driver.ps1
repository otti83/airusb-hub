# Static analysis of airusb.sys, WITHOUT loading it.
#
# WHY THIS EXISTS AS ITS OWN SCRIPT
#
# A kernel driver is the one thing in this project whose first mistake costs a
# bugcheck on a machine somebody has to be standing next to. Every other
# component can be run, watched and fixed in a loop; this one cannot. So the
# verification that CAN happen without running it has to actually happen, and
# has to be a command rather than an intention.
#
# `cl /analyze` with the kernel-mode annotations is the cheapest half of that.
# It reads the SAL on the WDK's own prototypes — `_IRQL_requires_max_`,
# `_Must_inspect_result_`, `_In_reads_bytes_` — and checks this driver against
# them. That is exactly the class of mistake a build cannot see and a first load
# discovers loudly: a PASSIVE_LEVEL call from a DISPATCH_LEVEL path, a status
# ignored, a buffer read past its stated length.
#
# It is NOT Static Driver Verifier. SDV proves KMDF *protocol* rules — the
# request-completion state machine, the cancel/complete race — and needs a real
# MSBuild project, which this driver deliberately does not have (see
# wdk-build-driver.ps1 for why). SDV remains a prerequisite before the first
# load and is written down in WINDOWS_IMPORTER_PLAN.md §W6 as one; this script
# is the part that can run today, unattended, over ssh.
$ErrorActionPreference = "Stop"

$kit = "C:\Program Files (x86)\Windows Kits\10"
$sdk = (Get-ChildItem "$kit\Include" -Directory |
        Where-Object { $_.Name -match '^\d+\.' -and (Test-Path (Join-Path $_.FullName 'km')) } |
        Sort-Object Name | Select-Object -Last 1).Name
$kmdf = (Get-ChildItem "$kit\Include\wdf\kmdf" -Directory | Sort-Object { [version]$_.Name } |
         Select-Object -Last 1).Name
$ude  = (Get-ChildItem "$kit\Include\$sdk\km\ude" -Directory | Sort-Object { [version]$_.Name } |
         Select-Object -Last 1).Name

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
$msvc = (Get-ChildItem "$vs\VC\Tools\MSVC" -Directory | Sort-Object Name | Select-Object -Last 1).FullName
$cl   = "$msvc\bin\Hostx64\x64\cl.exe"

Write-Host "SDK $sdk   KMDF $kmdf   UdeCx $ude   MSVC $(Split-Path $msvc -Leaf)"

$inc = @(
  "$kit\Include\$sdk\km"
  "$kit\Include\$sdk\shared"
  "$kit\Include\$sdk\ucrt"
  "$kit\Include\$sdk\km\ude\$ude"
  "$kit\Include\wdf\kmdf\$kmdf"
  "$msvc\include"
) | ForEach-Object { "/external:I`"$_`"" }

$defs = @("/D_AMD64_","/DAMD64","/D_WIN64","/DNTDDI_VERSION=0x0A000010",
          "/DKMDF_VERSION_MAJOR=1","/DKMDF_VERSION_MINOR=$($kmdf.Split('.')[1])")

New-Item -ItemType Directory -Force -Path build-drv | Out-Null

# /analyze:external- keeps the findings to OUR file. Without it the kit's own
# headers generate hundreds of warnings and the one that matters is invisible —
# the same reason the build uses /external:W0.
#
# NOT /WX here, deliberately. Analysis findings are read and judged, not
# silently promoted to build failures: a false positive in a driver is common
# and suppressing it blind is worse than reading it.
$out = & $cl /nologo /c /kernel /GS- /W4 /utf-8 /external:W0 /analyze /analyze:external- `
      /Fo"build-drv\\analyze_" `
      $defs $inc "platform\windows\driver\airusb_sys.c" 2>&1
$code = $LASTEXITCODE
$out | ForEach-Object { Write-Host $_ }

$findings = @($out | Where-Object { $_ -match ': warning C6| : warning C28| : warning C2650' })
Write-Host ""
if ($code -ne 0) {
    Write-Host "ANALYZE FAILED TO RUN (exit $code)"
    exit $code
}
Write-Host "CODE ANALYSIS: $($findings.Count) finding(s) in airusb_sys.c"
if ($findings.Count -eq 0) { Write-Host "CODE ANALYSIS PASS" }
exit 0
