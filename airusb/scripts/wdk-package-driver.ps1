# Package airusb.sys into an installable, TEST-SIGNED driver package.
#
# IT INSTALLS NOTHING AND LOADS NOTHING. It stamps the INF, builds the
# catalogue, makes a self-signed test certificate, signs both, and leaves a
# directory you can copy to the machine that will actually load it.
#
# WHY THIS RUNS ON THE BUILD MACHINE AND NOT THE BRING-UP MACHINE
#
# Because everything it does can go wrong in ways that look exactly like a
# broken driver once you are standing in front of a bugchecking box: a
# CatalogFile that does not match the INF, a missing architecture decoration, a
# certificate in the wrong store. Doing it here means that when the spare
# machine says "this device cannot start", the packaging is already excluded.
#
# Inf2Cat is also the only free syntax check this project has for an INF, and it
# is a genuinely strict one.
#
# WHAT IT DELIBERATELY DOES NOT DO
#
#   * it does not enable testsigning — that is a reboot on somebody's machine
#   * it does not install the package — that is `pnputil` / `devcon`, on the
#     machine nobody minds losing, with a person watching
#   * it does not produce anything shippable. An EV certificate and Microsoft
#     attestation are what distribution needs, and nobody has decided to do that
$ErrorActionPreference = "Stop"

$kit = "C:\Program Files (x86)\Windows Kits\10"
$sdk = (Get-ChildItem "$kit\Include" -Directory |
        Where-Object { $_.Name -match '^\d+\.' -and (Test-Path (Join-Path $_.FullName 'km')) } |
        Sort-Object Name | Select-Object -Last 1).Name

function Find-KitTool([string]$name, [string]$preferArch) {
    # x64 first, then anything. Inf2Cat ships x86-only and that is fine — it
    # runs under WOW64. Picking whatever `-Recurse` happened to return first is
    # how you end up trying to run the arm64 build on an AMD64 box.
    $all = Get-ChildItem -Path "$kit\bin","$kit\Tools","$kit\App Certification Kit" `
             -Filter $name -Recurse -ErrorAction SilentlyContinue
    $hit = $all | Where-Object { $_.FullName -match "\\$preferArch\\" } |
           Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $hit) { $hit = $all | Select-Object -First 1 }
    if (-not $hit) { throw "$name is not in this WDK install" }
    return $hit.FullName
}

$stampinf = Find-KitTool "stampinf.exe" "x64"
$inf2cat  = Find-KitTool "Inf2Cat.exe"  "x86"
$signtool = Find-KitTool "signtool.exe" "x64"
$makecert = Find-KitTool "MakeCert.exe" "x64"

Write-Host "SDK $sdk"
Write-Host "stampinf $stampinf"
Write-Host "inf2cat  $inf2cat"
Write-Host "signtool $signtool"

if (-not (Test-Path "build-drv\airusb.sys")) {
    throw "build-drv\airusb.sys is missing — run scripts\wdk-build-driver.ps1 first"
}

$out = "build-pkg"
Remove-Item -Recurse -Force $out -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $out | Out-Null
Copy-Item "build-drv\airusb.sys" $out
Copy-Item "platform\windows\driver\airusb.inf" $out

# A real DriverVer. Windows compares these, and an INF without one is refused
# outright with a message that does not say so.
$ver = (Get-Date -Format "MM/dd/yyyy") + ",1.0.0.0"
& $stampinf -f "$out\airusb.inf" -d * -v 1.0.0.0 -a amd64
if ($LASTEXITCODE -ne 0) { throw "stampinf failed" }
Write-Host "stamped DriverVer $ver"

# THE SYNTAX CHECK. Inf2Cat refuses an INF Windows would refuse, and it does it
# here rather than on the machine that is about to be rebooted.
& $inf2cat /driver:"$out" /os:10_x64 /verbose
if ($LASTEXITCODE -ne 0) { Write-Host "INF2CAT FAILED - the INF is not installable"; exit 1 }
Write-Host "catalogue built"

# A self-signed TEST certificate. Not a trust decision anybody should reuse:
# it exists so a machine with testsigning on will load this build, and for
# nothing else.
$certStore = "PrivateCertStore"
$certName  = "AirUSB Test Driver Signing"
& $makecert -r -pe -ss $certStore -n "CN=$certName" "$out\airusb-test.cer" 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "makecert failed" }

& $signtool sign /a /v /s $certStore /n $certName /fd sha256 /t http://timestamp.digicert.com `
    "$out\airusb.cat"
if ($LASTEXITCODE -ne 0) {
    # No network on a bring-up bench is normal. An untimestamped test signature
    # is fine — it only has to be valid while somebody is standing there.
    Write-Host "timestamping failed; signing without a timestamp"
    & $signtool sign /a /v /s $certStore /n $certName /fd sha256 "$out\airusb.cat"
    if ($LASTEXITCODE -ne 0) { throw "signtool failed" }
}
& $signtool sign /a /v /s $certStore /n $certName /fd sha256 "$out\airusb.sys"
if ($LASTEXITCODE -ne 0) { throw "signtool failed on the .sys" }

# The verify below is EXPECTED TO FAIL, and that is not a packaging error.
#
# `signtool verify /pa` applies the default authenticode policy, which requires
# a chain to a root the machine trusts. A self-signed test certificate has no
# such root until somebody imports it — which happens on the BRING-UP machine,
# deliberately, as part of turning testsigning on. A pass here would mean the
# build machine trusts a certificate this script just invented, which is the
# outcome nobody should want.
#
# So it is run for its diagnostic value and its result is reported, not obeyed.
#
# ErrorActionPreference is relaxed around it deliberately: with 'Stop', anything
# a native tool writes to stderr becomes a TERMINATING error in PowerShell, so
# the expected failure below would abort a script that had already succeeded.
# That is what made the first version exit 1 after printing PACKAGE BUILT.
$prevEap = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$verify = & $signtool verify /pa /v "$out\airusb.sys" 2>&1 | Out-String
$ErrorActionPreference = $prevEap
$global:LASTEXITCODE = 0
if ($verify -match "Successfully verified") {
    Write-Host "signature verifies against a trusted root on THIS machine"
} elseif ($verify -match "terminated in a root") {
    Write-Host "signature present; its root is untrusted here, which is correct for a"
    Write-Host "test certificate. It becomes trusted on the bring-up machine when the"
    Write-Host ".cer is imported into Trusted Root and Trusted Publisher (see W6)."
} else {
    Write-Host "signtool verify said something unexpected:"
    Write-Host $verify
}

Write-Host ""
Write-Host "PACKAGE BUILT - $out"
Get-ChildItem $out | ForEach-Object { "  {0,-24} {1,10:N0} bytes" -f $_.Name, $_.Length }
Write-Host ""
Write-Host "NOTHING WAS INSTALLED. Copy $out to the bring-up machine and follow"
Write-Host "WINDOWS_IMPORTER_PLAN.md section W6 - and read it BEFORE the reboot."
Write-Host ""
Write-Host "PACKAGE PASS"
exit 0
