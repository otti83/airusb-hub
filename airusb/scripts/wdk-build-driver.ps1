# Compile and link airusb.sys.
#
# COMPILING IS SAFE. LOADING IS NOT. This script deliberately stops at a .sys
# file on disk: a KMDF fault is a bugcheck, and on a machine reachable only over
# the network a boot loop is unrecoverable. Installation is a separate, manual,
# someone-is-at-the-keyboard step.
#
# No .vcxproj, for the same reason as the ABI check: a project file is another
# thing that can be configured differently from the answer you wanted.
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
$link = "$msvc\bin\Hostx64\x64\link.exe"

Write-Host "SDK $sdk   KMDF $kmdf   UdeCx $ude   MSVC $(Split-Path $msvc -Leaf)"

$inc = @(
  "$kit\Include\$sdk\km"
  "$kit\Include\$sdk\shared"
  "$kit\Include\$sdk\ucrt"
  "$kit\Include\$sdk\km\ude\$ude"
  "$kit\Include\wdf\kmdf\$kmdf"
  "$msvc\include"
) | ForEach-Object { "/external:I`"$_`"" }

# No /D_KERNEL_MODE: /kernel defines it, and defining a reserved macro on the
# command line is C4117, which /WX turns into a failure.
$defs = @("/D_AMD64_","/DAMD64","/D_WIN64","/DNTDDI_VERSION=0x0A000010",
          "/DKMDF_VERSION_MAJOR=1","/DKMDF_VERSION_MINOR=$($kmdf.Split('.')[1])")

New-Item -ItemType Directory -Force -Path build-drv | Out-Null

# /kernel is what makes cl reject C++ constructs a kernel cannot support.
# /GS- because the kernel supplies its own stack cookie support and the CRT one
# is not linked. /W4 /WX on OUR code, /external:W0 on the kit's.
& $cl /nologo /c /kernel /GS- /W4 /WX /utf-8 /external:W0 /Zi `
      /Fo"build-drv\\" /Fd"build-drv\airusb.pdb" `
      $defs $inc "platform\windows\driver\airusb_sys.c"
if ($LASTEXITCODE -ne 0) { Write-Host "COMPILE FAILED"; exit $LASTEXITCODE }
Write-Host "compiled"

# udecxstub.lib is what resolves UdecxFunctions / UdecxDriverGlobals — a class
# extension is linked, not merely included, and it is versioned alongside its
# headers. bufferoverflowfastfailk.lib supplies __security_init_cookie, which
# FxDriverEntry references and which /NODEFAULTLIB otherwise leaves dangling.
$libs = @(
  "$kit\Lib\$sdk\km\x64\ntoskrnl.lib"
  "$kit\Lib\$sdk\km\x64\wdmsec.lib"
  "$kit\Lib\$sdk\km\x64\hal.lib"
  "$kit\Lib\$sdk\km\x64\bufferoverflowfastfailk.lib"
  "$kit\Lib\$sdk\km\x64\ude\$ude\udecxstub.lib"
  "$kit\Lib\wdf\kmdf\x64\$kmdf\WdfDriverEntry.lib"
  "$kit\Lib\wdf\kmdf\x64\$kmdf\WdfLdr.lib"
)
foreach ($l in $libs) { if (-not (Test-Path $l)) { Write-Host "missing lib: $l"; exit 1 } }

& $link /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:FxDriverEntry /NODEFAULTLIB `
        /OUT:"build-drv\airusb.sys" /DEBUG /PDB:"build-drv\airusb.pdb" `
        "build-drv\airusb_sys.obj" $libs
if ($LASTEXITCODE -ne 0) { Write-Host "LINK FAILED"; exit $LASTEXITCODE }

Write-Host "DRIVER BUILD PASS - build-drv\airusb.sys"
Get-Item build-drv\airusb.sys | ForEach-Object { "  {0:N0} bytes" -f $_.Length }
