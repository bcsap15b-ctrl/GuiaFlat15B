param(
  [int]$Port = 8000
)

$ErrorActionPreference = 'Stop'
$script:RootPath = [System.IO.Path]::GetFullPath($PSScriptRoot)
$script:Sessions = @{}
$script:Iterations = 200000

function Send-Response {
  param(
    [System.Net.HttpListenerContext]$Context,
    [int]$StatusCode,
    [string]$Body,
    [string]$ContentType = 'text/plain; charset=utf-8'
  )

  $bytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
  $Context.Response.StatusCode = $StatusCode
  $Context.Response.ContentType = $ContentType
  $Context.Response.ContentLength64 = $bytes.Length
  $Context.Response.Headers['Cache-Control'] = 'no-store'
  $Context.Response.Headers['X-Content-Type-Options'] = 'nosniff'
  $Context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
  $Context.Response.Close()
}

function Send-Json {
  param(
    [System.Net.HttpListenerContext]$Context,
    [int]$StatusCode,
    [object]$Value
  )

  $json = ConvertTo-Json -InputObject $Value -Compress -Depth 8
  Send-Response -Context $Context -StatusCode $StatusCode -Body $json -ContentType 'application/json; charset=utf-8'
}

function Get-ConfigFilePath {
  param([string]$HtmlName)

  if ([string]::IsNullOrWhiteSpace($HtmlName) -or [System.IO.Path]::GetFileName($HtmlName) -ne $HtmlName -or $HtmlName -notmatch '^[A-Za-z0-9 _.-]+\.html?$') {
    throw 'Invalid HTML file name.'
  }

  $htmlPath = [System.IO.Path]::GetFullPath((Join-Path $script:RootPath $HtmlName))
  if (-not $htmlPath.StartsWith($script:RootPath + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Invalid HTML path.'
  }
  if (-not (Test-Path -LiteralPath $htmlPath -PathType Leaf)) {
    throw 'HTML file not found.'
  }

  $sysPath = [System.IO.Path]::ChangeExtension($htmlPath, '.sys')
  if (-not (Test-Path -LiteralPath $sysPath -PathType Leaf)) {
    throw 'Matching SYS file not found.'
  }

  return $sysPath
}

function Read-ConfigLines {
  param([string]$Path)

  return ,([System.IO.File]::ReadAllLines($Path, [System.Text.Encoding]::UTF8))
}

function Get-ConfigValues {
  param([string[]]$Lines)

  $values = [ordered]@{}
  foreach ($line in $Lines) {
    $trimmed = $line.Trim()
    if (-not $trimmed -or $trimmed.StartsWith('#') -or $trimmed.StartsWith('//')) { continue }
    $separator = $trimmed.IndexOf('=')
    if ($separator -lt 1) { continue }

    $key = $trimmed.Substring(0, $separator).Trim().ToUpperInvariant()
    $value = $trimmed.Substring($separator + 1).Trim()
    if ($key -match '^[A-Z][A-Z0-9_]*$') { $values[$key] = $value }
  }
  return $values
}

function Write-ConfigLines {
  param(
    [string]$Path,
    [string[]]$Lines
  )

  $temporaryPath = Join-Path $script:RootPath ([System.IO.Path]::GetRandomFileName())
  try {
    [System.IO.File]::WriteAllLines($temporaryPath, $Lines, (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
  }
  finally {
    if (Test-Path -LiteralPath $temporaryPath) { Remove-Item -LiteralPath $temporaryPath -Force }
  }
}

function New-PasswordHash {
  param([string]$Password)

  $salt = New-Object byte[] 16
  $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try { $random.GetBytes($salt) } finally { $random.Dispose() }

  $derive = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($Password, $salt, $script:Iterations)
  try { $hash = $derive.GetBytes(32) } finally { $derive.Dispose() }

  return 'pbkdf2-sha1${0}${1}${2}' -f $script:Iterations, [Convert]::ToBase64String($salt), [Convert]::ToBase64String($hash)
}

function Test-PasswordHash {
  param(
    [string]$Password,
    [string]$StoredHash
  )

  $parts = $StoredHash.Split('$')
  if ($parts.Length -ne 4 -or $parts[0] -ne 'pbkdf2-sha1') { return $false }

  try {
    $iterations = [int]$parts[1]
    if ($iterations -lt 100000 -or $iterations -gt 1000000) { return $false }
    $salt = [Convert]::FromBase64String($parts[2])
    $expected = [Convert]::FromBase64String($parts[3])
    $derive = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($Password, $salt, $iterations)
    try { $actual = $derive.GetBytes($expected.Length) } finally { $derive.Dispose() }
    $difference = 0
    for ($index = 0; $index -lt $expected.Length; $index++) {
      $difference = $difference -bor ($actual[$index] -bxor $expected[$index])
    }
    return $difference -eq 0
  }
  catch {
    return $false
  }
}

function Get-SessionHtmlName {
  param([System.Net.HttpListenerRequest]$Request)

  $cookie = $Request.Cookies['flat_session']
  if (-not $cookie -or -not $script:Sessions.ContainsKey($cookie.Value)) { return $null }
  return $script:Sessions[$cookie.Value]
}

function Set-SessionCookie {
  param(
    [System.Net.HttpListenerContext]$Context,
    [string]$HtmlName
  )

  $tokenBytes = New-Object byte[] 32
  $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try { $random.GetBytes($tokenBytes) } finally { $random.Dispose() }
  $token = [Convert]::ToBase64String($tokenBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
  $script:Sessions[$token] = $HtmlName
  $Context.Response.Headers.Add('Set-Cookie', "flat_session=$token; Path=/; HttpOnly; SameSite=Strict")
}

function Read-RequestJson {
  param([System.Net.HttpListenerRequest]$Request)

  $reader = New-Object System.IO.StreamReader($Request.InputStream, [System.Text.Encoding]::UTF8)
  try { return ConvertFrom-Json -InputObject $reader.ReadToEnd() } finally { $reader.Dispose() }
}

function Get-ContentType {
  param([string]$Extension)

  switch ($Extension.ToLowerInvariant()) {
    '.html' { return 'text/html; charset=utf-8' }
    '.css' { return 'text/css; charset=utf-8' }
    '.js' { return 'text/javascript; charset=utf-8' }
    '.png' { return 'image/png' }
    '.jpg' { return 'image/jpeg' }
    '.jpeg' { return 'image/jpeg' }
    '.svg' { return 'image/svg+xml' }
    '.ico' { return 'image/x-icon' }
    default { return 'application/octet-stream' }
  }
}

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://127.0.0.1:$Port/")
$listener.Start()
Write-Host "Flat app running at http://127.0.0.1:$Port/index.html"
Write-Host 'Press Ctrl+C to stop.'

try {
  while ($listener.IsListening) {
    $context = $listener.GetContext()
    try {
      $request = $context.Request
      $path = $request.Url.AbsolutePath

      if ($request.HttpMethod -eq 'GET' -and $path -match '^/api/config/([^/]+)$') {
        try {
          $sysPath = Get-ConfigFilePath -HtmlName ([Uri]::UnescapeDataString($Matches[1]))
          $lines = Read-ConfigLines -Path $sysPath
          $publicLines = @($lines | Where-Object { $_ -notmatch '^\s*SENHAHASH\s*=' })
          Send-Response -Context $context -StatusCode 200 -Body ($publicLines -join "`n")
        }
        catch { Send-Json -Context $context -StatusCode 404 -Value @{ error = $_.Exception.Message } }
      }
      elseif ($request.HttpMethod -eq 'GET' -and $path -match '^/api/session/([^/]+)$') {
        $htmlName = [Uri]::UnescapeDataString($Matches[1])
        try {
          $sysPath = Get-ConfigFilePath -HtmlName $htmlName
          $values = Get-ConfigValues -Lines (Read-ConfigLines -Path $sysPath)
          $sessionHtml = Get-SessionHtmlName -Request $request
          Send-Json -Context $context -StatusCode 200 -Value @{ authenticated = ($sessionHtml -eq $htmlName); hasPassword = $values.Contains('SENHAHASH') }
        }
        catch { Send-Json -Context $context -StatusCode 400 -Value @{ error = $_.Exception.Message } }
      }
      elseif ($request.HttpMethod -eq 'POST' -and $path -eq '/api/login') {
        try {
          $body = Read-RequestJson -Request $request
          $htmlName = [string]$body.htmlName
          $password = [string]$body.password
          if ([string]::IsNullOrEmpty($password)) { throw 'Digite a senha.' }

          $sysPath = Get-ConfigFilePath -HtmlName $htmlName
          $lines = Read-ConfigLines -Path $sysPath
          $values = Get-ConfigValues -Lines $lines
          if (-not $values.Contains('SENHAHASH')) {
            if ($password -cne '123456') {
              Send-Json -Context $context -StatusCode 401 -Value @{ error = 'Senha incorreta.' }
              continue
            }

            $lines = @($lines) + (New-PasswordHash -Password $password)
            $lines[$lines.Length - 1] = "SENHAHASH=$($lines[$lines.Length - 1])"
            Write-ConfigLines -Path $sysPath -Lines $lines
          }
          elseif (-not (Test-PasswordHash -Password $password -StoredHash $values['SENHAHASH'])) {
            Send-Json -Context $context -StatusCode 401 -Value @{ error = 'Senha incorreta.' }
            continue
          }

          Set-SessionCookie -Context $context -HtmlName $htmlName
          Send-Json -Context $context -StatusCode 200 -Value @{ authenticated = $true }
        }
        catch { Send-Json -Context $context -StatusCode 400 -Value @{ error = $_.Exception.Message } }
      }
      elseif ($request.HttpMethod -eq 'POST' -and $path -eq '/api/password/change') {
        try {
          $body = Read-RequestJson -Request $request
          $htmlName = [string]$body.htmlName
          $oldPassword = [string]$body.oldPassword
          $newPassword = [string]$body.newPassword
          $confirmPassword = [string]$body.confirmPassword
          if ([string]::IsNullOrEmpty($newPassword)) { throw 'Digite a nova senha.' }
          if ($newPassword -cne $confirmPassword) { throw "As novas senhas n$([char]0x00E3)o s$([char]0x00E3)o iguais." }

          $sysPath = Get-ConfigFilePath -HtmlName $htmlName
          $lines = Read-ConfigLines -Path $sysPath
          $values = Get-ConfigValues -Lines $lines
          if ($values.Contains('SENHAHASH')) {
            if (-not (Test-PasswordHash -Password $oldPassword -StoredHash $values['SENHAHASH'])) {
              Send-Json -Context $context -StatusCode 401 -Value @{ error = 'Senha anterior incorreta.' }
              continue
            }
          }
          elseif ($oldPassword -cne '123456') {
            Send-Json -Context $context -StatusCode 401 -Value @{ error = "A senha anterior inicial $([char]0x00E9) 123456." }
            continue
          }

          $hashLine = "SENHAHASH=$(New-PasswordHash -Password $newPassword)"
          $updated = New-Object System.Collections.Generic.List[string]
          $hashWritten = $false
          foreach ($line in $lines) {
            if ($line -match '^\s*SENHAHASH\s*=') {
              $updated.Add($hashLine)
              $hashWritten = $true
            }
            else {
              $updated.Add($line)
            }
          }
          if (-not $hashWritten) { $updated.Add($hashLine) }
          Write-ConfigLines -Path $sysPath -Lines $updated.ToArray()

          Set-SessionCookie -Context $context -HtmlName $htmlName
          Send-Json -Context $context -StatusCode 200 -Value @{ changed = $true }
        }
        catch { Send-Json -Context $context -StatusCode 400 -Value @{ error = $_.Exception.Message } }
      }
      elseif ($request.HttpMethod -eq 'POST' -and $path -eq '/api/config/save') {
        try {
          $body = Read-RequestJson -Request $request
          $htmlName = [string]$body.htmlName
          if ((Get-SessionHtmlName -Request $request) -ne $htmlName) { throw 'Sessao expirada. Entre novamente.' }

          $sysPath = Get-ConfigFilePath -HtmlName $htmlName
          $lines = Read-ConfigLines -Path $sysPath
          $values = @{}
          foreach ($property in $body.values.PSObject.Properties) {
            $key = $property.Name.ToUpperInvariant()
            $value = [string]$property.Value
            if ($key -notmatch '^[A-Z][A-Z0-9_]*$' -or $key -eq 'SENHAHASH' -or $value.Contains("`n") -or $value.Contains("`r")) {
              throw 'Parametro invalido.'
            }
            $values[$key] = $value
          }

          $updated = New-Object System.Collections.Generic.List[string]
          foreach ($line in $lines) {
            $trimmed = $line.Trim()
            $separator = $trimmed.IndexOf('=')
            if ($separator -gt 0) {
              $key = $trimmed.Substring(0, $separator).Trim().ToUpperInvariant()
              if ($values.ContainsKey($key)) {
                $updated.Add("$key=$($values[$key])")
                [void]$values.Remove($key)
                continue
              }
            }
            $updated.Add($line)
          }

          if ($values.Count -gt 0) { throw 'Nao e permitido criar ou renomear parametros.' }
          Write-ConfigLines -Path $sysPath -Lines $updated.ToArray()
          Send-Json -Context $context -StatusCode 200 -Value @{ saved = $true }
        }
        catch { Send-Json -Context $context -StatusCode 400 -Value @{ error = $_.Exception.Message } }
      }
      elseif ($request.HttpMethod -in @('GET', 'HEAD')) {
        $relativePath = [Uri]::UnescapeDataString($path.TrimStart('/')).Replace('/', [System.IO.Path]::DirectorySeparatorChar)
        if (-not $relativePath) { $relativePath = 'index.html' }
        $filePath = [System.IO.Path]::GetFullPath((Join-Path $script:RootPath $relativePath))
        $rootPrefix = $script:RootPath + [System.IO.Path]::DirectorySeparatorChar
        if (-not $filePath.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase) -or [System.IO.Path]::GetExtension($filePath) -in @('.sys', '.ps1')) {
          Send-Response -Context $context -StatusCode 404 -Body 'Not found'
          continue
        }
        if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
          Send-Response -Context $context -StatusCode 404 -Body 'Not found'
          continue
        }

        $bytes = [System.IO.File]::ReadAllBytes($filePath)
        $context.Response.StatusCode = 200
        $context.Response.ContentType = Get-ContentType -Extension ([System.IO.Path]::GetExtension($filePath))
        $context.Response.ContentLength64 = $bytes.Length
        $context.Response.Headers['Cache-Control'] = 'no-store'
        $context.Response.Headers['X-Content-Type-Options'] = 'nosniff'
        if ($request.HttpMethod -eq 'GET') { $context.Response.OutputStream.Write($bytes, 0, $bytes.Length) }
        $context.Response.Close()
      }
      else {
        Send-Json -Context $context -StatusCode 405 -Value @{ error = 'Method not allowed.' }
      }
    }
    catch {
      try { Send-Json -Context $context -StatusCode 500 -Value @{ error = 'Erro interno do servidor.' } } catch {}
      Write-Warning $_.Exception.Message
    }
  }
}
finally {
  $listener.Stop()
  $listener.Close()
}