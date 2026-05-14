<#
.SYNOPSIS
One-click upgrade script for old nuclei custom POC/templates.

.DESCRIPTION
Backs up a nuclei template directory, upgrades common deprecated protocol syntax,
and optionally runs nuclei -validate.

Main migrations:
  requests: -> http:
  network:  -> tcp:

The script is intentionally conservative. It only changes top-level YAML keys
that are commonly reported by nuclei v3 as deprecated protocol syntax.

.EXAMPLE
.\Upgrade-NucleiPoc.ps1 -TemplateDir "D:\tmp\anjian\pj\st\tmp\nuclei"

.EXAMPLE
.\Upgrade-NucleiPoc.ps1 -TemplateDir "D:\tmp\anjian\pj\st\tmp\nuclei" -NoValidate

.EXAMPLE
.\Upgrade-NucleiPoc.ps1 -TemplateDir "D:\tmp\anjian\pj\st\tmp\nuclei" -WhatIf
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TemplateDir,

    [ValidateNotNullOrEmpty()]
    [string]$NucleiPath = "nuclei",

    [switch]$NoBackup,

    [switch]$NoValidate,

    [switch]$VerboseValidate
)

$ErrorActionPreference = "Stop"

function Resolve-ExistingDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
    $item = Get-Item -LiteralPath $resolved.Path -ErrorAction Stop
    if (-not $item.PSIsContainer) {
        throw "TemplateDir is not a directory: $Path"
    }

    return $item.FullName
}

function New-BackupDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceDir
    )

    $parent = Split-Path -Parent $SourceDir
    $name = Split-Path -Leaf $SourceDir
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupDir = Join-Path $parent "$name.backup.$timestamp"

    Copy-Item -LiteralPath $SourceDir -Destination $backupDir -Recurse -Force
    return $backupDir
}

function Convert-NucleiTemplateContent {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Content
    )

    $updated = $Content

    # nuclei v2-style HTTP protocol key.
    $updated = [regex]::Replace($updated, '(?m)^requests(\s*):', 'http$1:')

    # nuclei v2-style network protocol key.
    $updated = [regex]::Replace($updated, '(?m)^network(\s*):', 'tcp$1:')

    return $updated
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Content
    )

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
}

$templateRoot = Resolve-ExistingDirectory -Path $TemplateDir
$startedAt = Get-Date
$changedFiles = New-Object System.Collections.Generic.List[string]
$wouldChangeFiles = New-Object System.Collections.Generic.List[string]
$scannedCount = 0
$backupPath = $null

Write-Host "[*] Template directory: $templateRoot"

if (-not $NoBackup) {
    if ($PSCmdlet.ShouldProcess($templateRoot, "Create backup directory")) {
        $backupPath = New-BackupDirectory -SourceDir $templateRoot
        Write-Host "[+] Backup created: $backupPath"
    }
} else {
    Write-Host "[!] Backup skipped because -NoBackup was specified"
}

$templateFiles = Get-ChildItem -LiteralPath $templateRoot -Recurse -File -Include *.yaml, *.yml

foreach ($file in $templateFiles) {
    $scannedCount++
    $path = $file.FullName
    $oldContent = [System.IO.File]::ReadAllText($path)
    $newContent = Convert-NucleiTemplateContent -Content $oldContent

    if ($newContent -ne $oldContent) {
        $wouldChangeFiles.Add($path) | Out-Null
        if ($PSCmdlet.ShouldProcess($path, "Upgrade deprecated nuclei protocol syntax")) {
            Write-Utf8NoBom -Path $path -Content $newContent
            $changedFiles.Add($path) | Out-Null
            Write-Host "[updated] $path"
        }
    }
}

Write-Host ""
Write-Host "[+] Upgrade pass finished"
Write-Host "    Files scanned : $scannedCount"
Write-Host "    Files updated : $($changedFiles.Count)"
if ($WhatIfPreference) {
    Write-Host "    Would update  : $($wouldChangeFiles.Count)"
}
if ($backupPath) {
    Write-Host "    Backup        : $backupPath"
}
Write-Host "    Started       : $($startedAt.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host "    Finished      : $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))"

if ($changedFiles.Count -gt 0) {
    $logPath = Join-Path (Get-Location) ("nuclei-upgrade-changed-files-{0}.txt" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $changedFiles | Set-Content -LiteralPath $logPath -Encoding UTF8
    Write-Host "[+] Changed file list: $logPath"
}

if ($WhatIfPreference -and $wouldChangeFiles.Count -gt 0) {
    $whatIfLogPath = Join-Path (Get-Location) ("nuclei-upgrade-would-change-files-{0}.txt" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $wouldChangeFiles | Set-Content -LiteralPath $whatIfLogPath -Encoding UTF8
    Write-Host "[+] Would-change file list: $whatIfLogPath"
}

if (-not $NoValidate) {
    Write-Host ""
    Write-Host "[*] Running nuclei validation..."

    $validateArgs = @("-t", $templateRoot, "-validate")
    if ($VerboseValidate) {
        $validateArgs += "-vv"
    }

    Write-Host "    $NucleiPath $($validateArgs -join ' ')"

    try {
        & $NucleiPath @validateArgs
        $exitCode = $LASTEXITCODE
        if ($exitCode -eq 0) {
            Write-Host "[+] nuclei validation passed"
        } else {
            Write-Host "[!] nuclei validation exited with code: $exitCode"
            Write-Host "    For detailed validation log, run:"
            Write-Host "    $NucleiPath -t `"$templateRoot`" -validate -vv 2>&1 | Tee-Object validate.log"
            if ($backupPath) {
                Write-Host "    Backup is available at: $backupPath"
            }
            exit $exitCode
        }
    } catch {
        Write-Host "[!] Failed to run nuclei validation: $($_.Exception.Message)"
        Write-Host "    If nuclei is not in PATH, pass -NucleiPath `"C:\path\to\nuclei.exe`""
        if ($backupPath) {
            Write-Host "    Backup is available at: $backupPath"
        }
        exit 2
    }
} else {
    Write-Host "[*] Validation skipped because -NoValidate was specified"
}
