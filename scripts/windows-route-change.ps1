# Run only on disposable machines: temporarily changes system-wide IPv4 routes.
# Requires elevation and DevCon from Microsoft's WDK (NETWATCH_DEVCON).
[CmdletBinding()]
param(
    [ValidateSet('Run', 'PreferA', 'PreferB')][string]$Action = 'Run',
    [string]$TestBinary
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# netwatch asks the stack for its routes to these documentation addresses.
$probes = @('192.0.2.1', '198.51.100.1', '203.0.113.1')

function ConvertTo-Number([string]$Address) {
    $b = [System.Net.IPAddress]::Parse($Address).GetAddressBytes()
    [uint64]$b[0] * 16777216 + [uint64]$b[1] * 65536 + [uint64]$b[2] * 256 + [uint64]$b[3]
}

function ConvertTo-Address([double]$Number) {
    $octets = foreach ($unit in 16777216, 65536, 256, 1) { [math]::Floor($Number / $unit) % 256 }
    $octets -join '.'
}

# Returns prefixes covering every IPv4 address outside the probes' /24 networks,
# by splitting 0.0.0.0/0 around them.
function Get-PrefixesAroundProbes {
    $excluded = foreach ($probe in $probes) { [math]::Floor((ConvertTo-Number $probe) / 256) * 256 }
    $pending = [System.Collections.Generic.Stack[object]]::new()
    $pending.Push(@(0, 0))
    while ($pending.Count -gt 0) {
        $start, $length = $pending.Pop()
        $size = [math]::Pow(2, 32 - $length)
        if (@($excluded | Where-Object { $_ -ge $start -and $_ -lt $start + $size }).Count -eq 0) {
            "$(ConvertTo-Address $start)/$length"
        } elseif ($length -lt 24) {
            $pending.Push(@(($start + $size / 2), ($length + 1)))
            $pending.Push(@($start, ($length + 1)))
        }
    }
}

function Assert-Default([int]$Expected) {
    $routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' |
        Sort-Object { $_.RouteMetric + $_.InterfaceMetric })
    $routes | Format-Table InterfaceIndex, DestinationPrefix, NextHop, RouteMetric, InterfaceMetric | Out-Host
    if ($routes.Count -lt 2 -or $routes[0].InterfaceIndex -ne $Expected -or
        ($routes[0].RouteMetric + $routes[0].InterfaceMetric) -eq
        ($routes[1].RouteMetric + $routes[1].InterfaceMetric)) {
        throw "Windows routing table does not uniquely prefer interface $Expected"
    }
    # Also check the stack's routes to netwatch's probe addresses, independently of netwatch.
    $selected = @(foreach ($probe in $probes) { Find-NetRoute -RemoteIPAddress $probe })
    $selected | Format-List | Out-Host
    if (@($selected | Where-Object { $_.InterfaceIndex -ne $Expected }).Count -ne 0) {
        throw "Windows source-address selection does not use interface $Expected"
    }
}

if ($Action -ne 'Run') {
    if ($env:NETWATCH_ROUTE_TEST -ne '1') { throw 'Run through the test harness' }
    # B stays at 100; moving A between 10 and 200 changes the winner in one operation.
    $metric = if ($Action -eq 'PreferA') { 10 } else { 200 }
    Get-NetRoute -InterfaceIndex $env:NETWATCH_ADAPTER_A -DestinationPrefix '0.0.0.0/0' |
        Set-NetRoute -RouteMetric $metric -Confirm:$false
    $expected = if ($Action -eq 'PreferA') { $env:NETWATCH_ADAPTER_A } else { $env:NETWATCH_ADAPTER_B }
    Assert-Default $expected
    exit 0
}

if (-not $TestBinary -or -not (Test-Path $TestBinary)) { throw 'Supply a compiled test executable' }
$devcon = $env:NETWATCH_DEVCON
if (-not $devcon -or -not (Test-Path $devcon)) { throw 'Set NETWATCH_DEVCON to the WDK devcon.exe' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator privileges are required'
}

$originalRoutes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' |
    Select-Object InterfaceIndex, DestinationPrefix, NextHop, RouteMetric, InterfaceMetric)
if ($originalRoutes.Count -eq 0) { throw 'Runner has no IPv4 default route' }
$uplink = $originalRoutes | Sort-Object { $_.RouteMetric + $_.InterfaceMetric } | Select-Object -First 1
$preservedRoutes = [System.Collections.Generic.List[object]]::new()
$devices = [System.Collections.Generic.List[string]]::new()
$process = $null
try {
    # Preserve runner Internet traffic while the probes follow the real default
    # routes. These more-specific routes cover every other IPv4 address.
    foreach ($prefix in Get-PrefixesAroundProbes) {
        $preservedRoutes.Add((New-NetRoute -InterfaceIndex $uplink.InterfaceIndex -DestinationPrefix $prefix `
            -NextHop $uplink.NextHop -RouteMetric 1 -PolicyStore ActiveStore))
    }
    # Keep the original default routes as fallbacks, saving their metrics above.
    foreach ($route in $originalRoutes) {
        Get-NetRoute -InterfaceIndex $route.InterfaceIndex -DestinationPrefix $route.DestinationPrefix -NextHop $route.NextHop |
            Set-NetRoute -RouteMetric 5000 -Confirm:$false
    }

    foreach ($slot in @('A', 'B')) {
        $before = @(Get-NetAdapter -IncludeHidden | Select-Object -ExpandProperty InterfaceGuid)
        & $devcon install "$env:SystemRoot\inf\netloop.inf" '*MSLOOP'
        if ($LASTEXITCODE -ne 0) { throw "DevCon install failed or requires reboot: $LASTEXITCODE" }
        $adapter = $null
        for ($attempt = 0; $attempt -lt 30; $attempt++) {
            $new = @(Get-NetAdapter -IncludeHidden | Where-Object { $_.InterfaceGuid -notin $before })
            if ($new.Count -eq 1) { $adapter = $new[0]; break }
            Start-Sleep -Seconds 1
        }
        if (-not $adapter) { throw 'Virtual Ethernet adapter did not appear' }
        $devices.Add($adapter.PnPDeviceID)
        $adapter | Rename-NetAdapter -NewName "netwatch-test-$slot"
    }
    # DevCon updates every device with the same hardware ID, which can reset the
    # first adapter when installing the second. Configure only after both exist.
    foreach ($slot in @('A', 'B')) {
        $adapter = Get-NetAdapter -Name "netwatch-test-$slot"
        $index = $adapter.InterfaceIndex
        Set-Item "Env:NETWATCH_ADAPTER_$slot" $index
        Set-Item "Env:NETWATCH_ADAPTER_${slot}_NAME" ([guid]$adapter.InterfaceGuid).ToString('B')
        Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4 -Dhcp Disabled -AutomaticMetric Disabled -InterfaceMetric 1
        $subnet = if ($slot -eq 'A') { '198.18.0' } else { '198.19.0' }
        New-NetIPAddress -InterfaceIndex $index -IPAddress "$subnet.2" -PrefixLength 24 | Out-Null
        # netdev resolves gateway MAC addresses with SendARP. Supply a permanent
        # neighbor for these synthetic gateways to avoid ARP timeouts and Windows
        # treating the test route as unreachable. No Internet service is simulated.
        $mac = if ($slot -eq 'A') { '02-00-00-00-00-0A' } else { '02-00-00-00-00-0B' }
        New-NetNeighbor -InterfaceIndex $index -IPAddress "$subnet.1" -LinkLayerAddress $mac -State Permanent | Out-Null
        $metric = if ($slot -eq 'A') { 10 } else { 100 }
        New-NetRoute -InterfaceIndex $index -DestinationPrefix '0.0.0.0/0' -NextHop "$subnet.1" `
            -RouteMetric $metric -PolicyStore ActiveStore | Out-Null
        for ($attempt = 0; $attempt -lt 30; $attempt++) {
            $address = Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv4 -IPAddress "$subnet.2"
            if ($address.AddressState -eq 'Preferred') { break }
            Start-Sleep -Seconds 1
        }
        if ($address.AddressState -ne 'Preferred') { throw 'Virtual adapter address did not become usable' }
    }
    Assert-Default $env:NETWATCH_ADAPTER_A
    Get-NetAdapter | Format-Table Name, InterfaceIndex, Status | Out-Host
    $env:NETWATCH_ROUTE_TEST = '1'
    $process = Start-Process -FilePath $TestBinary -ArgumentList @('--ignored', '--exact', 'windows_default_route_change', '--nocapture') -NoNewWindow -PassThru
    # Retain the handle so Windows PowerShell can read ExitCode after exit.
    $null = $process.Handle
    if (-not $process.WaitForExit(120000)) { throw 'Route test exceeded its two-minute deadline' }
    if ($process.ExitCode -ne 0) { throw "Route test failed with exit code $($process.ExitCode)" }
} finally {
    if ($process -and -not $process.HasExited) { $process.Kill(); $process.WaitForExit() }
    # Restore connectivity first, including after assertion failures or timeout.
    foreach ($device in $devices) {
        & $devcon remove "@$device"
        if ($LASTEXITCODE -ne 0) { Write-Warning "Could not remove test device $device" }
    }
    foreach ($route in $originalRoutes) {
        Get-NetRoute -InterfaceIndex $route.InterfaceIndex -DestinationPrefix $route.DestinationPrefix -NextHop $route.NextHop |
            Set-NetRoute -RouteMetric $route.RouteMetric -Confirm:$false
    }
    foreach ($route in $preservedRoutes) { $route | Remove-NetRoute -Confirm:$false }
    Remove-Item Env:NETWATCH_ROUTE_TEST -ErrorAction SilentlyContinue
    Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Format-Table | Out-Host
}
