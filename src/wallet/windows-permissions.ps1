# Wallet filesystem protections only. Input is public paths/actions on stdin.
# No keys, network access, execution-policy changes, or antivirus configuration.
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = New-Object Text.UTF8Encoding($false)
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
function Invoke-WalletFileRequest($request) {
  if ($request.action -notin @('host', 'mkdir', 'protect', 'verify')) { throw 'Unknown action' }
  if ($request.action -eq 'host') {
    return [Microsoft.Win32.Registry]::GetValue('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography', 'MachineGuid', $null)
  }
  $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
  foreach ($path in $request.paths) {
    if ($request.action -eq 'mkdir') {
      $acl = New-Object Security.AccessControl.DirectorySecurity
      $acl.SetOwner($sid)
      $acl.SetAccessRuleProtection($true, $false)
      $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
      $acl.AddAccessRule($rule)
      [IO.Directory]::CreateDirectory($path, $acl) | Out-Null
    }
    $attrs = [IO.File]::GetAttributes($path)
    if (($attrs -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse point' }
    $isDir = ($attrs -band [IO.FileAttributes]::Directory) -ne 0
    if ($request.action -eq 'protect') {
      if ($isDir) { $acl = New-Object Security.AccessControl.DirectorySecurity }
      else { $acl = New-Object Security.AccessControl.FileSecurity }
      $acl.SetOwner($sid)
      $acl.SetAccessRuleProtection($true, $false)
      if ($isDir) { $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow') }
      else { $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'Allow') }
      $acl.AddAccessRule($rule)
      if ($isDir) { [IO.Directory]::SetAccessControl($path, $acl) }
      else { [IO.File]::SetAccessControl($path, $acl) }
    }
    if ($isDir) { $acl = [IO.Directory]::GetAccessControl($path) }
    else { $acl = [IO.File]::GetAccessControl($path) }
    if (!$acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value) { throw 'Wrong owner or inherited DACL' }
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($rules.Count -eq 0) { throw 'Empty DACL' }
    foreach ($rule in $rules) {
      if ($rule.IdentityReference.Value -ne $sid.Value -or $rule.AccessControlType -ne 'Allow' -or $rule.FileSystemRights -ne 'FullControl') { throw 'Non-owner access' }
    }
  }
  return ''
}
# One response per request, in order. EOF also exits after an abrupt parent death.
# Never cache permission results or return exception text (which can contain paths).
try {
  while ($null -ne ($line = [Console]::In.ReadLine())) {
    try {
      $request = $line | ConvertFrom-Json
      $value = Invoke-WalletFileRequest $request
      $response = @{ ok = $true; value = [string]$value }
    } catch { $response = @{ ok = $false } }
    [Console]::Out.WriteLine(($response | ConvertTo-Json -Compress))
    [Console]::Out.Flush()
  }
} catch { exit 1 }
