# api_push_commit.ps1 - Push a local commit to GitHub via REST API (bypasses blocked github.com:443).
#
# How it works: commit/tree/blob SHAs are pure functions of content. We recreate the
# objects byte-for-byte through the API, so GitHub computes the SAME commit SHA as the
# local one - remote and local stay in perfect sync, zero divergence.
# Prereq: the commit's parent tree must match the current remote ref (fast-forward),
# otherwise the ref update is refused.
#
# Token comes from `git credential fill` (one-time GCM browser authorization, then it
# lives in Windows Credential Manager).
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\api_push_commit.ps1 -CommitSha <sha>
param(
    [Parameter(Mandatory=$true)][string]$CommitSha,
    [string]$RepoDir = "E:\TwinStar",
    [string]$Owner = "Ainxin-1",
    [string]$Repo = "TwinStar",
    [string]$RemoteBranch = "main",
    [string]$TokenFile = "$env:TEMP\ts_cred.txt"
)
$ErrorActionPreference = "Stop"

function GitBytes([string[]]$GitArgs) {
    # Capture raw bytes via .NET Process BaseStream (avoids PS text-pipeline mangling)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "$env:ProgramFiles\Git\bin\git.exe"
    $psi.Arguments = (@("-C", "`"$RepoDir`"") + $GitArgs) -join " "
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $ms = New-Object System.IO.MemoryStream
    $p.StandardOutput.BaseStream.CopyTo($ms)
    $errText = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    if ($p.ExitCode -ne 0) { throw "git $($GitArgs -join ' ') failed (exit $($p.ExitCode)): $errText" }
    return $ms.ToArray()
}
function GitText([string[]]$GitArgs) {
    [Text.Encoding]::UTF8.GetString((GitBytes $GitArgs))
}

if (-not (Test-Path $TokenFile)) {
    # get token straight from GCM (silent once stored in Windows Credential Manager;
    # pops the browser auth dialog only on first ever use). Start-Process avoids the
    # bash-wrapper `<` redirection mangling that breaks `git credential fill`.
    $ask = "$env:TEMP\ts_ask.txt"
    [IO.File]::WriteAllText($ask, "protocol=https`nhost=github.com`n")
    $credOut = "$env:TEMP\ts_cred.txt"
    $credErr = "$env:TEMP\ts_cred_err.txt"
    $env:PATH += ";$env:ProgramFiles\Git\cmd;$env:ProgramFiles\Git\bin"
    $gcm = "$env:ProgramFiles\Git\mingw64\bin\git-credential-manager.exe"
    if (-not (Test-Path $gcm)) { throw "git-credential-manager.exe not found at $gcm" }
    Start-Process -FilePath $gcm -ArgumentList "get" -RedirectStandardInput $ask `
        -RedirectStandardOutput $credOut -RedirectStandardError $credErr -Wait -NoNewWindow
}
$raw = [IO.File]::ReadAllText($TokenFile)
if ($raw -notmatch 'password=(\S+)') { throw "no password= line in token file" }
$token = $Matches[1]
$headers = @{
    Authorization          = "Bearer $token"
    Accept                 = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
}
$api = "https://api.github.com/repos/$Owner/$Repo"
function Api([string]$Method, [string]$Uri, $Body) {
    # use curl.exe: PS 5.1 Invoke-RestMethod mangles UTF-8 bodies and 422s on byte[] payloads
    $tmpOut = [IO.Path]::GetTempFileName()
    $curlArgs = @("-s", "-X", $Method, "-H", "Authorization: Bearer $token",
        "-H", "Accept: application/vnd.github+json", "-o", $tmpOut, "-w", "%{http_code}")
    if ($null -ne $Body) {
        $tmpIn = [IO.Path]::GetTempFileName()
        [IO.File]::WriteAllText($tmpIn, ($Body | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))
        $curlArgs += @("-H", "Content-Type: application/json", "--data-binary", "@$tmpIn")
    }
    $code = (& curl.exe @curlArgs $Uri | Select-Object -Last 1).Trim()
    $outText = [IO.File]::ReadAllText($tmpOut)
    Remove-Item $tmpOut -ErrorAction SilentlyContinue
    if ($Body -and $tmpIn) { Remove-Item $tmpIn -ErrorAction SilentlyContinue }
    if ($code -notmatch '^2\d\d$') {
        $errText = ""
        try { $errText = ($outText | ConvertFrom-Json).message } catch { }
        throw "API $Method $Uri failed (HTTP $code): $errText"
    }
    return $outText | ConvertFrom-Json
}

# ---- 1. Parse local commit object ----
$full = (GitText @("rev-parse", $CommitSha)).Trim()
if ($full.Length -ne 40) { throw "not a valid commit: $CommitSha" }
$obj = GitText @("cat-file", "commit", $full)
$obj = $obj.Replace("`r`n", "`n")
$idx = $obj.IndexOf("`n`n")
if ($idx -lt 0) { throw "unexpected commit object layout (no header/message separator)" }
$header  = $obj.Substring(0, $idx)
$message = $obj.Substring($idx + 2)
$treeSha = $null; $parentSha = $null; $authorRaw = $null; $commitRaw = $null
foreach ($h in ($header -split "`n")) {
    if ($h -match '^tree ([0-9a-f]{40})$')         { $treeSha = $Matches[1] }
    elseif ($h -match '^parent ([0-9a-f]{40})$')   { $parentSha = $Matches[1] }
    elseif ($h -match '^author (.+)$')             { $authorRaw = $Matches[1] }
    elseif ($h -match '^committer (.+)$')          { $commitRaw = $Matches[1] }
}
if (-not $treeSha -or -not $parentSha -or -not $authorRaw -or -not $commitRaw) {
    throw "unexpected commit header (single-parent commits only)"
}

function ParseIdent([string]$line) {
    if ($line -notmatch '^(.+) <(.+)> (\d+) ([+-]\d{4})\s*$') { throw "cannot parse ident line: $line" }
    $name = $Matches[1]; $email = $Matches[2]
    $unix = [long]$Matches[3]; $tz = $Matches[4]
    $sign = $(if ($tz[0] -eq '-') { -1 } else { 1 })
    $offMin = $sign * ([int]$tz.Substring(1, 2) * 60 + [int]$tz.Substring(3, 2))
    $iso = [DateTimeOffset]::FromUnixTimeSeconds($unix).ToOffset([TimeSpan]::FromMinutes($offMin)).ToString("yyyy-MM-dd'T'HH:mm:sszzz")
    @{ name = $name; email = $email; date = $iso }
}
$author    = ParseIdent $authorRaw
$committer = ParseIdent $commitRaw

Write-Host "local commit : $full"
Write-Host "  tree       : $treeSha"
Write-Host "  parent     : $parentSha"

# ---- 2. Remote state ----
$ref = Api GET "$api/git/ref/heads/$RemoteBranch" $null
Write-Host "remote $RemoteBranch at : $($ref.object.sha)"
if ($ref.object.sha -eq $full) { Write-Host "remote already up to date."; exit 0 }
if ($ref.object.sha -ne $parentSha) {
    throw "remote ($($ref.object.sha)) is not the local parent ($parentSha); not a fast-forward, refusing."
}
$parentCommit = Api GET "$api/git/commits/$parentSha" $null
$parentTree = $parentCommit.tree.sha

# ---- 3. Changed files -> upload missing blobs ----
$diffText = GitText @("diff-tree", "-r", "--no-commit-id", "--name-status", $full)
$entries = @()
foreach ($line in ($diffText -split "`n" | Where-Object { $_.Trim() })) {
    $parts = $line -split "`t"
    if ($parts.Count -lt 2) { continue }
    $status = $parts[0].Trim(); $path = $parts[1].Trim()
    if ($status -eq 'D') {
        $entries += @{ path = $path; mode = "100644"; type = "blob"; sha = $null }
        Write-Host "  D  $path"
        continue
    }
    if ($status -eq 'A' -or $status -eq 'M') {
        $blobSha = (GitText @("rev-parse", "${full}:$path")).Trim()
        $modeLine = GitText @("ls-tree", $full, "--", $path)
        if ($modeLine -match '^(\d{6}) ') { $mode = $Matches[1] } else { $mode = "100644" }
        # skip upload when remote already has the identical blob
        $exists = $true
        try { Api GET "$api/git/blobs/$blobSha" $null | Out-Null } catch { $exists = $false }
        if (-not $exists) {
            $bytes = GitBytes @("cat-file", "blob", $blobSha)
            # PS 把空 byte[] 传给 .NET 方法会变 null（空文件场景）
            if ($null -eq $bytes) { $bytes = [byte[]]@() }
            $b64 = [Convert]::ToBase64String($bytes)
            $newBlob = Api POST "$api/git/blobs" @{ content = $b64; encoding = "base64" }
            if ($newBlob.sha -ne $blobSha) { throw "blob SHA mismatch: remote $($newBlob.sha) != local $blobSha ($path)" }
            Write-Host "  uploaded blob $blobSha ($path)"
        } else {
            Write-Host "  reused  blob $blobSha ($path)"
        }
        $entries += @{ path = $path; mode = $mode; type = "blob"; sha = $blobSha }
    } else {
        throw "unsupported diff status '$status' ($path) - split renames into A/D first"
    }
}

# ---- 4. Build tree (base_tree = remote parent tree), verify SHA matches local ----
$newTree = Api POST "$api/git/trees" @{ base_tree = $parentTree; tree = $entries }
if ($newTree.sha -ne $treeSha) {
    throw "tree SHA mismatch: remote $($newTree.sha) != local $treeSha; aborted, remote ref untouched."
}
Write-Host "tree recreated : $($newTree.sha)"

# ---- 5. Create commit (byte-identical author/committer/message), verify SHA ----
$newCommit = Api POST "$api/git/commits" @{
    message   = $message
    tree      = $treeSha
    parents   = @($parentSha)
    author    = $author
    committer = $committer
}
if ($newCommit.sha -ne $full) {
    throw "commit SHA mismatch: remote $($newCommit.sha) != local $full; aborted, remote ref untouched."
}
Write-Host "commit recreated : $($newCommit.sha)"

# ---- 6. Fast-forward the ref ----
$updated = Api PATCH "$api/git/refs/heads/$RemoteBranch" @{ sha = $full; force = $false }
Write-Host "OK: remote $RemoteBranch advanced to $($updated.object.sha)"
