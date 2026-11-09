<#
.SYNOPSIS
  Local signing helper for the JAdES demo page (smart cards / Windows certificate store).

.DESCRIPTION
  A browser cannot use a smart card's private key, so this script does it for the page.
  It listens on http://127.0.0.1:<Port>/ only and offers two calls:

    GET  /certs  -> certificates in CurrentUser\My that have a private key
                    (smart-card certificates appear there through the card's minidriver)
    POST /sign   {thumbprint, alg, data}  -> {signature}
                    data      = Base64URL of the JWS signing input (ASCII protected.payload)
                    signature = Base64URL of the raw signature
                                PS256: RSASSA-PSS, SHA-256, MGF1-SHA-256, salt 32
                                ES256: ECDSA P-256, SHA-256, 64-byte R||S

  Windows shows its own PIN prompt when the card needs it; the key never leaves the card.
  Every request must carry the access token printed at startup (header X-Helper-Token),
  so other web pages open in the browser cannot use the helper.

  Runs on Windows PowerShell 5.1 with no installation. Stop with Ctrl+C.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File demo\smartcard-helper.ps1
#>
param(
  [int]$Port = 8765
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security

function ConvertTo-B64Url([byte[]]$bytes) {
  [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-B64Url([string]$s) {
  if ($s -notmatch '^[A-Za-z0-9_-]*$') { throw 'data is not Base64URL' }
  $std = $s.Replace('-', '+').Replace('_', '/')
  switch ($std.Length % 4) { 2 { $std += '==' } 3 { $std += '=' } 1 { throw 'data is not Base64URL' } }
  [Convert]::FromBase64String($std)
}

function Get-SigningCertificates {
  Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.HasPrivateKey }
}

function Invoke-Sign($req) {
  $thumb = [string]$req.thumbprint
  $alg = [string]$req.alg
  $cert = Get-SigningCertificates | Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1
  if (-not $cert) { throw "certificate $thumb not found in CurrentUser\My" }
  $data = ConvertFrom-B64Url ([string]$req.data)
  $sha256 = [System.Security.Cryptography.HashAlgorithmName]::SHA256

  switch ($alg) {
    'PS256' {
      $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
      if (-not $rsa) { throw 'PS256 needs an RSA key; this certificate is not RSA' }
      if ($rsa.KeySize -lt 2048) { throw "RSA key is $($rsa.KeySize) bit; at least 2048 is required" }
      try {
        # .NET uses salt length = hash length (32 bytes) for PSS.
        $sig = $rsa.SignData($data, $sha256, [System.Security.Cryptography.RSASignaturePadding]::Pss)
      } catch {
        throw "the key provider refused RSA-PSS (old CSP keys cannot do PSS): $($_.Exception.InnerException.Message)$($_.Exception.Message)"
      }
    }
    'ES256' {
      $ec = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert)
      if (-not $ec) { throw 'ES256 needs an EC key; this certificate is not EC' }
      if ($ec.KeySize -ne 256) { throw "ES256 needs P-256; this key is $($ec.KeySize) bit" }
      # Windows CNG returns IEEE P1363 (R||S), which is what JWS needs.
      $sig = $ec.SignData($data, $sha256)
      if ($sig.Length -ne 64) { throw "unexpected ECDSA signature length $($sig.Length)" }
    }
    default { throw "unsupported alg '$alg' (PS256 or ES256)" }
  }
  Write-Host ("  signed {0} bytes with {1} [{2}]" -f $data.Length, $cert.Subject, $alg)
  @{ signature = (ConvertTo-B64Url $sig) }
}

function Send-Json($ctx, [int]$status, $obj) {
  $res = $ctx.Response
  $res.StatusCode = $status
  $res.ContentType = 'application/json; charset=utf-8'
  $bytes = [Text.Encoding]::UTF8.GetBytes(($obj | ConvertTo-Json -Depth 5 -Compress))
  $res.ContentLength64 = $bytes.Length
  $res.OutputStream.Write($bytes, 0, $bytes.Length)
  $res.Close()
}

$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$tokenBytes = New-Object byte[] 16
$rng.GetBytes($tokenBytes)
$token = -join ($tokenBytes | ForEach-Object { $_.ToString('x2') })

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://127.0.0.1:$Port/")
$listener.Start()

Write-Host ''
Write-Host "JAdES smart-card helper listening on http://127.0.0.1:$Port"
Write-Host "Access token (paste it into the page): " -NoNewline
Write-Host $token -ForegroundColor Yellow
Write-Host 'Ctrl+C to stop.'
Write-Host ''

try {
  while ($listener.IsListening) {
    $pending = $listener.GetContextAsync()
    while (-not $pending.AsyncWaitHandle.WaitOne(500)) { }   # lets Ctrl+C through
    $ctx = $pending.Result
    $req = $ctx.Request
    $res = $ctx.Response

    # CORS: the page may be opened from file:// (origin "null") or any local server.
    $res.AddHeader('Access-Control-Allow-Origin', '*')
    $res.AddHeader('Access-Control-Allow-Headers', 'X-Helper-Token, Content-Type')
    $res.AddHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    $res.AddHeader('Access-Control-Allow-Private-Network', 'true')

    Write-Host ("{0} {1} {2}" -f (Get-Date -Format 'HH:mm:ss'), $req.HttpMethod, $req.Url.AbsolutePath)
    try {
      if ($req.HttpMethod -eq 'OPTIONS') { $res.StatusCode = 204; $res.Close(); continue }
      if ($req.Headers['X-Helper-Token'] -ne $token) { Send-Json $ctx 401 @{ error = 'wrong or missing access token (see the helper window)' }; continue }

      switch ("$($req.HttpMethod) $($req.Url.AbsolutePath)") {
        'GET /certs' {
          $list = @(Get-SigningCertificates | ForEach-Object {
            @{ thumbprint = $_.Thumbprint; subject = $_.Subject; der = [Convert]::ToBase64String($_.RawData) }
          })
          Send-Json $ctx 200 @{ certificates = $list }
        }
        'POST /sign' {
          $reader = New-Object IO.StreamReader($req.InputStream, [Text.Encoding]::UTF8)
          $body = $reader.ReadToEnd() | ConvertFrom-Json
          Send-Json $ctx 200 (Invoke-Sign $body)
        }
        default { Send-Json $ctx 404 @{ error = 'not found' } }
      }
    } catch {
      Write-Host "  error: $($_.Exception.Message)" -ForegroundColor Red
      try { Send-Json $ctx 400 @{ error = $_.Exception.Message } } catch { }
    }
  }
} finally {
  $listener.Stop()
  $listener.Close()
}
