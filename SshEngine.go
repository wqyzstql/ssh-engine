package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SSHConfig holds the configuration parsed from ssh config file
type SSHConfig struct {
	Host          string
	HostName      string
	User          string
	Port          string
	IdentityFile  string
	RemoteCommand string
	LogFileName   string
	ProxyJump     []string // Array of proxy hosts
}

func main() {
	// Read SSH config
	config, err := readSSHConfig("config", "target-host")
	if err != nil {
		fmt.Printf("Error reading SSH config: %s\n", err)
		os.Exit(1)
	}

	debugLogging := false
	// Setup logging if a log file name was passed in
	if config.LogFileName != "" {
		file, err := os.OpenFile("engine.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()
		log.SetOutput(file)
		debugLogging = true
	}

	// Setup the client configuration
	sshConfig := getSshConfig(config)

	// Create the final client connection through proxy if needed
	var client *ssh.Client
	var err1 error

	if len(config.ProxyJump) > 0 {
		client, err1 = createProxyJumpConnection(config, sshConfig)
	} else {
		server := fmt.Sprintf("%s:%s", config.HostName, config.Port)
		client, err1 = ssh.Dial("tcp", server, sshConfig)
	}

	if err1 != nil {
		fmt.Printf("Could not connect to ssh. Error is: %s\n", err1)
		os.Exit(1)
	}
	defer client.Close()

	// Start a session
	session, err := client.NewSession()
	if err != nil {
		fmt.Printf("Failed to create ssh session. Error is: %s\n", err)
		os.Exit(1)
	}
	defer session.Close()

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	// StdinPipe for commands
	stdin, _ := session.StdinPipe()

	// Start remote shell
	if err := session.Shell(); err != nil {
		fmt.Printf("Failed to start shell. Error is: %s\n", err)
		os.Exit(1)
	}

	// Run the supplied command first
	if config.RemoteCommand != "" {
		fmt.Fprintf(stdin, "%s\n", config.RemoteCommand)
	}

	// Accepting commands
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		if debugLogging {
			log.Println("Input: " + scanner.Text())
		}
		fmt.Fprintf(stdin, "%s\n", scanner.Text())
		if scanner.Text() == "quit" {
			if debugLogging {
				log.Println("Quit sent")
			}
			break
		}
	}
}

func createProxyJumpConnection(config *SSHConfig, sshConfig *ssh.ClientConfig) (*ssh.Client, error) {
	var client *ssh.Client

	// Connect through each proxy in the chain
	for i, proxyHost := range config.ProxyJump {
		proxyConfig, err := readSSHConfig("config", proxyHost)
		if err != nil {
			return nil, fmt.Errorf("error reading proxy config for %s: %w", proxyHost, err)
		}

		proxyAddr := fmt.Sprintf("%s:%s", proxyConfig.HostName, proxyConfig.Port)

		if i == 0 {
			// First proxy connection
			client, err = ssh.Dial("tcp", proxyAddr, getSshConfig(proxyConfig))
		} else {
			// Connect through existing proxy
			conn, err := client.Dial("tcp", proxyAddr)
			if err != nil {
				return nil, fmt.Errorf("error connecting to proxy %s: %w", proxyHost, err)
			}

			ncc, chans, reqs, err := ssh.NewClientConn(conn, proxyAddr, getSshConfig(proxyConfig))
			if err != nil {
				return nil, fmt.Errorf("error creating proxy connection to %s: %w", proxyHost, err)
			}

			client = ssh.NewClient(ncc, chans, reqs)
		}

		if err != nil {
			return nil, fmt.Errorf("error connecting to proxy %s: %w", proxyHost, err)
		}
	}

	// Connect to final destination through the proxy chain
	finalAddr := fmt.Sprintf("%s:%s", config.HostName, config.Port)
	conn, err := client.Dial("tcp", finalAddr)
	if err != nil {
		return nil, fmt.Errorf("error connecting to final destination: %w", err)
	}

	ncc, chans, reqs, err := ssh.NewClientConn(conn, finalAddr, sshConfig)
	if err != nil {
		return nil, fmt.Errorf("error creating final connection: %w", err)
	}

	return ssh.NewClient(ncc, chans, reqs), nil
}

func getSshConfig(config *SSHConfig) *ssh.ClientConfig {
	key, err := getKeyFile(config.IdentityFile)
	if err != nil {
		fmt.Printf("Could not read private key file at %s\n", config.IdentityFile)
		os.Exit(1)
	}

	sshConfig := &ssh.ClientConfig{
		User: config.User,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		// Add support for different key exchange algorithms if needed
		// Config.KeyExchanges = []string{"diffie-hellman-group-exchange-sha256", "diffie-hellman-group14-sha1"}
	}
	return sshConfig
}

func getKeyFile(file string) (key ssh.Signer, err error) {
	// Expand ~ to home directory if present
	if strings.HasPrefix(file, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		file = filepath.Join(home, file[1:])
	}

	buf, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("error reading the key file: %w", err)
	}

	key, err = ssh.ParsePrivateKey(buf)
	if err != nil {
		return nil, fmt.Errorf("error parsing the private key file: %w", err)
	}

	return key, nil
}

func readSSHConfig(configFile, targetHost string) (*SSHConfig, error) {
	// Default values
	config := &SSHConfig{
		Port:      "22",
		ProxyJump: make([]string, 0),
	}

	// Expand ~ to home directory if present in config file path
	if strings.HasPrefix(configFile, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		configFile = filepath.Join(home, configFile[1:])
	}

	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	var currentHost string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		key := strings.ToLower(parts[0])
		value := strings.Join(parts[1:], " ")

		switch key {
		case "host":
			currentHost = value
			if currentHost == targetHost {
				config.Host = targetHost
			}
		default:
			if currentHost == targetHost {
				switch key {
				case "hostname":
					config.HostName = value
				case "user":
					config.User = value
				case "port":
					config.Port = value
				case "identityfile":
					config.IdentityFile = value
				case "remotecommand":
					config.RemoteCommand = value
				case "logfile":
					config.LogFileName = value
				case "proxyjump":
					// Split ProxyJump value into array of hosts
					proxyHosts := strings.Split(value, ",")
					for _, host := range proxyHosts {
						config.ProxyJump = append(config.ProxyJump, strings.TrimSpace(host))
					}
				}
			}
		}
	}

	// Validate required fields
	if config.Host == "" {
		return nil, fmt.Errorf("host %s not found in config file", targetHost)
	}
	if config.HostName == "" {
		config.HostName = config.Host
	}
	if config.User == "" {
		return nil, fmt.Errorf("user not specified for host %s", targetHost)
	}
	if config.IdentityFile == "" {
		return nil, fmt.Errorf("identity file not specified for host %s", targetHost)
	}

	return config, nil
}
