Update: Change the configuration file format to SSH config file, added support for commands such as ProxyJump, but only in Windows test passed!



When using some chess software like Chessbase, you may need an executable that is a proxy to a remote chess engine. This simple program is meant just for that.

Specifically, it builds an .exe that you can point to that just connects to a remote server using SSH. There is an external config file that you use so you can change the settings without needing to build a new .exe file.

This will work on linux of MacOS as well, but for those systems it may be easier to make your own script. But, if you want to use this, just build it for those environments.

More details can be found here: https://mattplayschess.com/ssh-engine/

## Setup

You will need to pull down the dependencies for Go:

```
go get ssh-engine
```

## Configuration

Create a filed called `engine.yml` in the same directory. The contents should look like this but for your configuration:

Mac/Linux:

```yml
user: "matt"
privateKeyFile: "/Users/matt/.ssh/stockfish-keypair.pem"
host: "123.45.67.8"
port: "22"
remoteCommand: "stockfish"
```

Windows:

```yml
user: "matt"
privateKeyFile: "C:\\Users\\matt\\.ssh\\stockfish-keypair.pem"
host: "123.45.67.8"
port: "22"
remoteCommand: "stockfish"
```

If you want to enable extra logging, add this to the configuration file with the name of your log file:

```yml
logFileName: "engine.log"
```

## Running

Run the proxy:

```
go run SshEngine.go
```

## Troubleshooting

Here are some common error messages and possible causes:

>>>
Could not connect to ssh (failed to dial). Error is: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain
>>>

Make sure the key file is one that can be used by the remote host. SSHEngine can connect to the remote computer, but cannot authenticate with the given private key.

>>>
Could not connect to ssh (failed to dial). Error is: dial tcp: lookup 123.45.67.8: no such host
>>>

SSHEngine could not find the remote host. Make sure the IP address is correct.

>>>
Could not connect to ssh (failed to dial). Error is: dial tcp 123.45.67.8:22: connectex: A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond.
>>>

SSHEngine could probably find the remote host, but still can't connect. Check to make sure the port is open and accepting connections.

>>>
Error reading the key file. Error is: open C:\Users\matt\.ssh\stockfish_keypair.pem: The system cannot find the file specified.
>>>

Make sure your configuration file has the correct `privateKeyFile` configured.

>>>
Error parsing the private key file. Is this a valid private key? Error is: ssh: no key found
>>>

Make sure you are using a valid private key file. Make sure it is not a public key, it has to be your private key

## Building

To build an executable for Windows:

```
env GOOS=windows GOARCH=386 go build SshEngine.go
```

This will create SshEngine.exe. Copy that along with the config file to a suitable directory on Windows.

## Making a Release

Create a tag (format `0.0.0`) and the CI pipeline will automatically build a Windows .exe and create a release

```
git tag 0.0.3
git push origin --tags
```
