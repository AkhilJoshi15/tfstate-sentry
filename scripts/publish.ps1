param(
    [string]$RepoUrl = "https://github.com/AkhilJoshi15/tfstate-sentry.git"
)

$ErrorActionPreference = "Stop"
$SourceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ("tfstate-sentry-publish-" + [guid]::NewGuid().ToString("N"))
$RepoDir = Join-Path $WorkDir "repo"

try {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        throw "git is required"
    }

    git clone $RepoUrl $RepoDir
    if ($LASTEXITCODE -ne 0) { throw "git clone failed" }

    $RoboArgs = @(
        $SourceRoot,
        $RepoDir,
        "/MIR",
        "/XD", ".git", "bin", "dist",
        "/R:1",
        "/W:1",
        "/NFL",
        "/NDL",
        "/NJH",
        "/NJS"
    )
    & robocopy @RoboArgs | Out-Null
    if ($LASTEXITCODE -gt 7) { throw "robocopy failed with exit code $LASTEXITCODE" }

    Push-Location $RepoDir
    try {
        git add --all
        git diff --cached --quiet
        if ($LASTEXITCODE -eq 0) {
            Write-Host "No changes to publish."
            exit 0
        }

        $UserName = git config user.name
        $UserEmail = git config user.email
        if ([string]::IsNullOrWhiteSpace($UserName) -or [string]::IsNullOrWhiteSpace($UserEmail)) {
            throw "Configure git user.name and user.email before publishing."
        }

        git commit -m "feat: publish initial Terraform state exposure scanner"
        if ($LASTEXITCODE -ne 0) { throw "git commit failed" }

        git push origin main
        if ($LASTEXITCODE -ne 0) { throw "git push failed" }

        Write-Host "Published main. Review the CI workflow before creating tag v0.1.0."
    }
    finally {
        Pop-Location
    }
}
finally {
    if (Test-Path $WorkDir) {
        Remove-Item -Recurse -Force $WorkDir
    }
}
