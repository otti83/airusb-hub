# Compile platform/windows/wdk_abi_check.c against the real WDK headers.
#
# This is the ONLY way the constants in WindowsUsbAbi.h get verified. The file
# emits no code and is never linked: if cl.exe accepts it, every C_ASSERT in it
# held, and the transcription is confirmed. If it does not, one of the numbers
# is wrong and the tables built on it are wrong with it.
#
# Deliberately not a .vcxproj. A project file is another thing that can be
# configured differently from the answer you wanted, and this needs to be
# reproducible by anyone with a WDK and no opinions.
$ErrorActionPreference = "Stop"

$kit = "C:\Program Files (x86)\Windows Kits\10"
$sdk = (Get-ChildItem "$kit\Include" -Directory |
        Where-Object { $_.Name -match '^\d+\.' -and (Test-Path (Join-Path $_.FullName 'km')) } |
        Sort-Object Name | Select-Object -Last 1).Name
$kmdf = (Get-ChildItem "$kit\Include\wdf\kmdf" -Directory | Sort-Object { [version]$_.Name } |
         Select-Object -Last 1).Name
$ude  = (Get-ChildItem "$kit\Include\$sdk\km\ude" -Directory | Sort-Object { [version]$_.Name } |
         Select-Object -Last 1).Name

Write-Host "SDK $sdk   KMDF $kmdf   UdeCx $ude"

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
$msvc = (Get-ChildItem "$vs\VC\Tools\MSVC" -Directory | Sort-Object Name | Select-Object -Last 1).FullName
$cl = "$msvc\bin\Hostx64\x64\cl.exe"

# ucrt is required even for a kernel-mode compile: ntdef.h reaches ctype.h.
# Leaving it out gives "cannot open include file 'ctype.h'", which reads like a
# broken WDK and is really a missing path.
$inc = @(
  "$kit\Include\$sdk\km"
  "$kit\Include\$sdk\shared"
  "$kit\Include\$sdk\ucrt"
  "$kit\Include\$sdk\km\ude\$ude"
  "$kit\Include\wdf\kmdf\$kmdf"
  "$msvc\include"
) | ForEach-Object { "/external:I`"$_`"" }

# _AMD64_ and the kernel defines are what ntddk.h expects from a driver build.
$defs = @("/D_AMD64_","/DAMD64","/D_WIN64","/D_KERNEL_MODE","/DNTDDI_VERSION=0x0A000010")

# /utf-8 is not optional: the sources carry em dashes, the console here is
# CP932, and without it cl warns C4819 and /WX turns that into a failure.
#
# The kit's headers go in with /external:I and /external:W0. Under a plain /I
# they are "our" code, so /WX promotes the WDK's own C4324 alignment padding
# warnings into failures — an error in wdfrequest.h that has nothing to do with
# us. Our file stays at /W4 /WX, which is the part worth being strict about.
& $cl /nologo /c /W4 /WX /utf-8 /external:W0 /Zs $defs $inc `
      /I"platform\windows" "platform\windows\wdk_abi_check.c"
if ($LASTEXITCODE -eq 0) {
  Write-Host "ABI CHECK PASS - every transcribed constant matches the WDK"
} else {
  Write-Host "ABI CHECK FAIL - exit $LASTEXITCODE"
  exit $LASTEXITCODE
}
