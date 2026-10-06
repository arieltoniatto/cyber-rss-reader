# Remove only the forwarding/firewall configuration created for Cyber RSS.
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
    throw 'Open PowerShell as Administrator to remove the Windows port proxy and firewall rule.'
}
foreach ($value in @($LanAddress, $WslAddress)) {
    $parsed = [System.Net.IPAddress]::Parse($value)
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw 'IPv4 addresses are required.'
    }
}
$ruleName = "CyberRssHttpsLAN-$Port"
$proxies = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp' -ErrorAction SilentlyContinue
$existingProxy = if ($proxies) { $proxies.PSObject.Properties["$LanAddress/$Port"] } else { $null }
$rule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
if ($existingProxy -and $existingProxy.Value -ne "$WslAddress/$Port") {
    throw 'The forwarding target differs from the Cyber RSS configuration; it was preserved.'
}
if ($rule) {
    $addresses = $rule | Get-NetFirewallAddressFilter
    $ports = $rule | Get-NetFirewallPortFilter
    if ($rule.Direction -ne 'Inbound' -or $rule.Action -ne 'Allow' -or
        $addresses.LocalAddress -ne $LanAddress -or $addresses.RemoteAddress -ne 'LocalSubnet' -or
        $ports.LocalPort -ne "$Port" -or $ports.Protocol -ne 'TCP') {
        throw 'The firewall rule differs from the Cyber RSS configuration; it was preserved.'
    }
}
if ($existingProxy) {
    & netsh interface portproxy delete v4tov4 listenaddress=$LanAddress listenport=$Port
    if ($LASTEXITCODE -ne 0) { throw "Port proxy removal failed: $LASTEXITCODE" }
}
if ($rule) { Remove-NetFirewallRule -Name $ruleName }
Write-Output 'Cyber RSS LAN forwarding and firewall rule removed.'
