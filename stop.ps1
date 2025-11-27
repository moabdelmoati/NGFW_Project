# Stop NGFW Project
$ports = @(5000, 3000)
foreach ($port in $ports) {
    $conns = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue | Where-Object {$_.State -eq "Listen"}
    foreach ($c in $conns) {
        $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
        if ($p) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
}
Write-Host "✅ Stopped all services" -ForegroundColor Green






