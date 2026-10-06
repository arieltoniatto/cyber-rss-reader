# Run in an elevated Windows PowerShell. Only the chosen private LAN address is published.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$LanAddress,
    [Parameter(Mandatory = $true)][string]$WslAddress,
    [ValidateRange(1, 65535)][int]$Port = 8443
)
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open PowerShell as Administrator to configure the Windows port proxy and firewall.'
}
function Assert-PrivateIPv4([string]$Value) {
    $parsed = [System.Net.IPAddress]::Parse($Value)
    $bytes = $parsed.GetAddressBytes()
    if ($bytes.Length -ne 4 -or -not ($bytes[0] -eq 10 -or
        ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 168))) {
        throw "A private IPv4 address is required: $Value"
    }
}
Assert-PrivateIPv4 $LanAddress
Assert-PrivateIPv4 $WslAddress
if (-not (Get-NetIPAddress -AddressFamily IPv4 -IPAddress $LanAddress -ErrorAction SilentlyContinue)) {
    throw 'The selected LAN address does not belong to this Windows host.'
}
$ruleName = "CyberRssHttpsLAN-$Port"
$proxyKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp'
$property = "$LanAddress/$Port"
$proxies = Get-ItemProperty $proxyKey -ErrorAction SilentlyContinue
$existingProxy = if ($proxies) { $proxies.PSObject.Properties[$property] } else { $null }
$existingRule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
if ($existingProxy -and $existingProxy.Value -ne "$WslAddress/$Port" -and -not $existingRule) {
    throw 'An unrelated forwarding rule already uses this address and port; it was preserved.'
}
if (-not $existingProxy -and (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalAddress -eq $LanAddress -or $_.LocalAddress -eq '0.0.0.0' })) {
    throw 'An existing listener uses this LAN port; it was preserved.'
}
if ($existingRule) {
    $addresses = $existingRule | Get-NetFirewallAddressFilter
    $ports = $existingRule | Get-NetFirewallPortFilter
    if ($existingRule.Direction -ne 'Inbound' -or $existingRule.Action -ne 'Allow' -or
        $addresses.LocalAddress -ne $LanAddress -or $addresses.RemoteAddress -ne 'LocalSubnet' -or
        $ports.LocalPort -ne "$Port" -or $ports.Protocol -ne 'TCP') {
        throw 'An existing firewall rule differs from the intended LAN-only rule; it was preserved.'
    }
} else {
    New-NetFirewallRule -Name $ruleName -DisplayName "Cyber RSS HTTPS LAN ($Port)" `
        -Direction Inbound -Action Allow -Protocol TCP -LocalAddress $LanAddress `
        -LocalPort $Port -RemoteAddress LocalSubnet -Profile Any | Out-Null
}
try {
    & netsh interface portproxy add v4tov4 listenaddress=$LanAddress listenport=$Port `
        connectaddress=$WslAddress connectport=$Port protocol=tcp
    if ($LASTEXITCODE -ne 0) { throw "Port proxy creation failed: $LASTEXITCODE" }
} catch {
    if (-not $existingRule) { Remove-NetFirewallRule -Name $ruleName }
    throw
}
Write-Output "LAN HTTPS forwarding configured: https://${LanAddress}:$Port"
Write-Output 'Trust the generated ca.crt on each client and use the credentials from access.txt.'
Write-Output 'After a WSL IP change, run this script again with the updated WslAddress.'
