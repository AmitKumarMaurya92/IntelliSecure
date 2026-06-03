$excludeFiles = @('*.sqlite3','*.db','*.pyc','*.png','*.jpg','*.ico','*.pdf','*.pptx','*.git*')

Get-ChildItem -Path "d:\IntelliSecure" -File -Recurse -Exclude $excludeFiles | ForEach-Object {
    if ($_.DirectoryName -notmatch "\\node_modules" -and $_.DirectoryName -notmatch "\\\.git" -and $_.DirectoryName -notmatch "\\__pycache__" -and $_.DirectoryName -notmatch "\\venv" -and $_.DirectoryName -notmatch "\\\.gemini") {
        try {
            $content = Get-Content $_.FullName -Raw -ErrorAction Stop
            if ($content -cmatch "IntelliSecure") {
                $content = $content -creplace "IntelliSecure", "IntelliSecure"
                [System.IO.File]::WriteAllText($_.FullName, $content, [System.Text.Encoding]::UTF8)
                Write-Host "Updated $($_.FullName)"
            }
        } catch {
            # Ignore binary or access-denied files
        }
    }
}
