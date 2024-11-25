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

Create a filed called `config` in the same directory. The contents should look like this but for your configuration:

Windows:

```yml
Host JumpMacnhine1
    HostName 1.1.1.1
    User yourusername
    IdentityFile path/to/your/sshkey
  
Host target-host
    HostName 2.2.2.2
    User yourusername
    IdentityFile path/to/your/sshkey
    ProxyJump JumpMacnhine1
    RemoteCommand path/to/stockfish
```

## Running

Run the proxy:

```
go run SshEngine.go
```

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
