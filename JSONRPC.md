# JSON-RPC Endpoint

## Cleanup

```ps
.\amd64\wireguard.exe /uninstallmanagerservice
Remove-Item -Path "C:\Program Files\WireGuard" -Recurse -Force

```

## Named Pipe Terminal

```ps
"C:\Program Files\PuTTY\plink.exe" -serial \\.\pipe\graicc\wiregurd-manager-jsonrpc
```

## Create or Update tunnel

NOTE: Stop/Start cycle requires to apply tunnel update

Request:

```json
{"method":"create","params":{"tunnelName":"wg0"},"id":1,"jsonrpc":"2.0"}

{"method":"create","params":{"tunnelName":"wg0","privateKey":"YOdXSeVOxKPnw8ty7/Ls2AuuyDo3AGYP0PhV6tewr1M="},"id":1,"jsonrpc":"2.0"}

{"method":"create","params":{"tunnelName":"wg0","listenPort":51280,"privateKey":"YOdXSeVOxKPnw8ty7/Ls2AuuyDo3AGYP0PhV6tewr1M=","addresses":["10.0.0.1/32"]},"id":1,"jsonrpc":"2.0"}

{"method":"create","params":{"tunnelName":"wg0","listenPort":51280,"privateKey":"YOdXSeVOxKPnw8ty7/Ls2AuuyDo3AGYP0PhV6tewr1M=","addresses":["10.0.0.1/32"],"peers":[{"publicKey":"V5UDIlVATpoaIeqFo3Vsn7YmdJj7lXE4wfLCVkRhaTs=","allowedIPs":["10.0.0.2/32"],"endpoint":"192.168.254.148:51280"}]},"id":1,"jsonrpc":"2.0"}

{"method":"create","params":{"tunnelName":"wg0","listenPort":51280,"privateKey":"YOdXSeVOxKPnw8ty7/Ls2AuuyDo3AGYP0PhV6tewr1M=","addresses":["10.0.0.1/32"],"peers":[{"publicKey":"V5UDIlVATpoaIeqFo3Vsn7YmdJj7lXE4wfLCVkRhaTs=","allowedIPs":["10.0.0.2/32"],"endpoint":"192.168.254.148:51280"},{"publicKey":"E1yYWin1KbwetAdRq2Dyigwv4oSGCWLbDUQnx1yYo93q","allowedIPs":["10.0.0.3/32"],"endpoint":"192.168.254.20:51280"}]},"id":1,"jsonrpc":"2.0"}
```

Response Success:

```json
{"result":null,"id":1,"jsonrpc":"2.0"}
```

Response Error:

```json
{"error":{"code":-32603,"message":"Access is denied."},"id":"1","jsonrpc":"2.0"}
```

## Start tunnel

Request:

```json
{"method":"start","params":{"tunnelName":"wg0"},"id":1,"jsonrpc":"2.0"}
```

Response Success:

```json
{"result":null,"id":1,"jsonrpc":"2.0"}
```

Response Error:

```json
{"error":{"code":-32603,"message":"open C:\\Program Files\\WireGuard\\Data\\Configurations\\wg0.conf.dpapi: The system cannot find the file specified."},"id":1,"jsonrpc":"2.0"}
```

## Stop tunnel

Request:

```json
{"method":"stop","params":{"tunnelName":"wg0"},"id":1,"jsonrpc":"2.0"}
```

Response Success:

```json
{"result":null,"id":1,"jsonrpc":"2.0"}
```

Response Error:

```json
TBD
```

## Delete tunnel

Request:

```json
{"method":"delete","params":{"tunnelName":"wg0"},"id":1,"jsonrpc":"2.0"}
```

Response Success:

```json
{"result":null,"id":1,"jsonrpc":"2.0"}
```

Response Error:

```json
TBD
```

## List tunnels

Request:

```json
{"method":"list","id":1,"jsonrpc":"2.0"}
```

Response Success:

```json
{"result":null,"id":1,"jsonrpc":"2.0"}
```

Response Error:

```json
TBD
```
