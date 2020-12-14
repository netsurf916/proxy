package socks5

import (
	"bufio"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"proxy/filter"
	"strconv"
	"sync"
	"syscall"
)

// Context for Socks5 server
type Context struct {
	Logger            chan string
	ClientConnections chan ClientCtx
	DomainFilter      filter.Filter
	ListenAddress     string
	Proxies           ProxyPool
	ReportIP          net.IP
}

func (ctx *Context) catchExit() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		ctx.Logger <- "\r [!] ctrl-c detected, exiting\n"
		ctx.DomainFilter.Save()
		os.Exit(0)
	}()
}

func (ctx *Context) logError(err error) {
	if ctx.Logger != nil {
		ctx.Logger <- fmt.Sprintf(" [!] Error: %s\n", err.Error())
	}
}

// Listen for inbound Socks5 connections
func (ctx *Context) Listen() error {
	// Listen does not exit, so setup a handler for ctrl-c
	go ctx.catchExit()
	defer close(ctx.ClientConnections)
	listener, err := net.Listen("tcp", ctx.ListenAddress)
	if err != nil {
		return err
	}
	if ctx.Logger != nil {
		ctx.Logger <- fmt.Sprintf(" [*] Bound to: %s\n", ctx.ListenAddress)
	}
	for {
		connection, err := listener.Accept()
		if err != nil {
			break
		}
		ctx.ClientConnections <- ClientCtx{Ctx: *ctx, Client: Connection{Connection: connection}}
	}
	return err
}

// HandleClients waits for client connections via the specified channel
func (ctx *Context) HandleClients() {
	for {
		client, ok := <-ctx.ClientConnections
		if ok == false {
			return
		}
		host, port, err := net.SplitHostPort(client.Client.Connection.RemoteAddr().String())
		if err != nil {
			return
		}
		client.Client.Host = host
		client.Client.Port, err = strconv.Atoi(port)
		if err != nil {
			return
		}
		go client.processClient()
	}
}

// ProxyInfo for outbound SOCKS5 servers
type ProxyInfo struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	UseTLS   bool   `json:"usetls"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// ProxyPool for known outbound SOCKS5 servers
type ProxyPool struct {
	Hosts []ProxyInfo
}

// LoadFile retrieves a SOCKS5 connection list from a file
func (ctx *ProxyPool) LoadFile(file string) bool {
	input, err := os.Open(file)
	if err != nil {
		return false
	}
	defer input.Close()
	finfo, err := input.Stat()
	if err != nil {
		return false
	}
	data := make([]byte, finfo.Size())
	_, err = input.Read(data)
	if err != nil {
		return false
	}
	err = json.Unmarshal(data, &ctx.Hosts)
	if err != nil {
		return false
	}
	return true
}

// Connection information
type Connection struct {
	Host       string
	Port       int
	Connection net.Conn
	Reader     *bufio.Reader
	Writer     *bufio.Writer
	ReadCount  uint64
}

// CopyData between connections
func (ctx *Connection) CopyData(other *Connection, wait *sync.WaitGroup) {
	defer wait.Done()
	for {
		n, err := io.Copy(ctx.Writer, other.Reader)
		if err != nil || n <= 0 {
			return
		}
		other.ReadCount += uint64(n)
	}
}

// ClientCtx for client connections
type ClientCtx struct {
	sync.Mutex
	Ctx         Context
	Client      Connection
	Remote      Connection
	RequestData []byte
	Proxy       ProxyInfo
}

// processInbound connections
func (ctx *ClientCtx) processInbound() (err error) {
	// State machine variables
	state := 0
	store := 0
	data := byte(0)

	// Execute state machine
	for state < 13 {
		// Read 1 byte from the connection
		data, err = ctx.Client.Reader.ReadByte()
		if err != nil {
			break
		}

		switch state {
		case 0:
			// Version 5
			if data == 0x05 {
				state = 1
				break
			}
			err = fmt.Errorf("invalid data(0) from: %s", ctx.Client.Host)
			state = 13
		case 1:
			// Number of supported authentication methods
			if data > 0 {
				store = int(data)
				state = 2
				break
			}
			err = fmt.Errorf("invalid data(1) from: %s", ctx.Client.Host)
			state = 13
		case 2:
			// Authentication methods (ignored for now)
			store--
			if store > 0 {
				break
			}
			fallthrough
		case 3:
			// Respond with no authenticaiton required
			_, err = ctx.Client.Writer.Write([]byte{0x05, 0x00})
			if err != nil {
				state = 13
				break
			}
			err = ctx.Client.Writer.Flush()
			if err != nil {
				state = 13
				break
			}
			state = 4
		case 4:
			// Version 5
			if data == 0x05 {
				state = 5
				break
			}
			err = fmt.Errorf("invalid data(4) from: %s", ctx.Client.Host)
			state = 13
		case 5:
			// Connect command
			if data == 0x01 {
				state = 6
				break
			}
			// Ignore other commands
			err = fmt.Errorf("invalid data(5) from: %s", ctx.Client.Host)
			state = 13
		case 6:
			// Reserved
			ctx.RequestData = append(ctx.RequestData, data)
			state = 7
		case 7:
			ctx.RequestData = append(ctx.RequestData, data)
			// IPv4 address
			if data == 0x01 {
				store = 4
				state = 8
			}
			// Domain name
			if data == 0x03 {
				store = 0
				state = 9
			}
			// IPv6
			if data == 0x04 {
				store = 16
				state = 11
			}
		case 8:
			// IPv4
			ctx.RequestData = append(ctx.RequestData, data)
			store--
			ctx.Remote.Host += strconv.Itoa(int(data))
			if store == 0 {
				store = 2
				state = 12
			} else {
				ctx.Remote.Host += "."
			}
		case 9:
			// Domain name length
			ctx.RequestData = append(ctx.RequestData, data)
			store = int(data)
			state = 10
		case 10:
			// Domain name
			ctx.RequestData = append(ctx.RequestData, data)
			store--
			ctx.Remote.Host += string([]byte{data})
			if store == 0 {
				store = 2
				state = 12
			}
		case 11:
			// IPv6
			ctx.RequestData = append(ctx.RequestData, data)
			store--
			ctx.Remote.Host += hex.EncodeToString([]byte{data})
			if store > 0 && store%2 == 0 {
				ctx.Remote.Host += ":"
			}
			if store == 0 {
				store = 2
				state = 12
			}
		case 12:
			// Port
			ctx.Remote.Port <<= 8
			ctx.Remote.Port += int(data)
			store--
			if store == 0 {
				state = 13
			}
		}
	}
	return err
}

// processOutbound connection
func (ctx *ClientCtx) processOutbound() (err error) {
	// State machine variables
	state := 0
	store := 0
	data := byte(0)
	proxyport := uint16(0)
	var response []byte

	// If no proxy list is available, connect to the destination directly and return
	if len(ctx.Ctx.Proxies.Hosts) == 0 {
		ctx.Remote.Connection, err = net.Dial("tcp", net.JoinHostPort(ctx.Remote.Host, strconv.Itoa(ctx.Remote.Port)))
		if err == nil {
			ctx.Remote.Reader = bufio.NewReader(ctx.Remote.Connection)
			ctx.Remote.Writer = bufio.NewWriter(ctx.Remote.Connection)
			// Get local port
			proxyport = uint16(ctx.Remote.Connection.LocalAddr().(*net.TCPAddr).Port)
			// Respond with success (version = 0x05, result = 0x00, reserved = 0x00)
			ctx.Client.Writer.Write([]byte{0x05, 0x00, 0x00})
			// Add the proxy IP
			reportIP := ctx.Ctx.ReportIP.To4()
			if reportIP != nil {
				// Type IPv4
				ctx.Client.Writer.Write([]byte{0x01})
				ctx.Client.Writer.Write(reportIP)
			} else {
				// Type IPv6
				ctx.Client.Writer.Write([]byte{0x04})
				ctx.Client.Writer.Write(ctx.Ctx.ReportIP)
			}
			// Local port
			ctx.Client.Writer.Write([]byte{byte((proxyport >> 8) & 0xFF), byte(proxyport & 0xFF)})
			ctx.Client.Writer.Flush()
		} else {
			// Respond with general error (0x01)
			ctx.Client.Writer.Write([]byte{0x05, 0x01})
			ctx.Client.Writer.Write(ctx.RequestData)
			// Local port is undefined
			ctx.Client.Writer.Write([]byte{0x00, 0x00})
			ctx.Client.Writer.Flush()
			ctx.Ctx.logError(err)
		}
		return err
	}

	// Select an outbound proxy at random
	ctx.Proxy = ctx.Ctx.Proxies.Hosts[rand.Intn(len(ctx.Ctx.Proxies.Hosts))]
	if len(ctx.Proxy.Username) > 255 || len(ctx.Proxy.Password) > 255 {
		// Respond with general error (0x01)
		ctx.Client.Writer.Write([]byte{0x05, 0x01})
		ctx.Client.Writer.Write(ctx.RequestData)
		// Local port is undefined
		ctx.Client.Writer.Write([]byte{0x00, 0x00})
		ctx.Client.Writer.Flush()
		ctx.Ctx.logError(err)
		return fmt.Errorf("provided username or password is too long: %s", ctx.Proxy.Host)
	}

	// Connect to proxy
	if ctx.Proxy.UseTLS {
		ctx.Remote.Connection, err = tls.Dial("tcp", net.JoinHostPort(ctx.Proxy.Host, strconv.Itoa(ctx.Proxy.Port)), &tls.Config{
			//InsecureSkipVerify: true,
		})
	} else {
		ctx.Remote.Connection, err = net.Dial("tcp", net.JoinHostPort(ctx.Proxy.Host, strconv.Itoa(ctx.Proxy.Port)))
	}
	if err != nil {
		// Respond with general error (0x01)
		ctx.Client.Writer.Write([]byte{0x05, 0x01})
		ctx.Client.Writer.Write(ctx.RequestData)
		// Local port is undefined
		ctx.Client.Writer.Write([]byte{0x00, 0x00})
		ctx.Client.Writer.Flush()
		ctx.Ctx.logError(err)
		return err
	}

	// Setup reader/writer
	ctx.Remote.Reader = bufio.NewReader(ctx.Remote.Connection)
	ctx.Remote.Writer = bufio.NewWriter(ctx.Remote.Connection)

	// Send initial SOCK5 request
	authType := byte(0) // No authentication
	if len(ctx.Proxy.Username) > 0 || len(ctx.Proxy.Password) > 0 {
		authType = byte(2) // User/pass auth type
	}
	_, err = ctx.Remote.Writer.Write([]byte{0x05, 0x01, authType})
	if err != nil {
		// Respond with general error (0x01)
		ctx.Client.Writer.Write([]byte{0x05, 0x01})
		ctx.Client.Writer.Write(ctx.RequestData)
		// Local port is undefined
		ctx.Client.Writer.Write([]byte{0x00, 0x00})
		ctx.Client.Writer.Flush()
		ctx.Ctx.logError(err)
		ctx.Remote.Connection.Close()
		return err
	}
	err = ctx.Remote.Writer.Flush()
	if err != nil {
		// Respond with general error (0x01)
		ctx.Client.Writer.Write([]byte{0x05, 0x01})
		ctx.Client.Writer.Write(ctx.RequestData)
		// Local port is undefined
		ctx.Client.Writer.Write([]byte{0x00, 0x00})
		ctx.Client.Writer.Flush()
		ctx.Ctx.logError(err)
		ctx.Remote.Connection.Close()
		return err
	}

	// Execute state machine
	for state < 15 {
		// Read 1 byte from the connection
		data, err = ctx.Remote.Reader.ReadByte()
		if err != nil {
			ctx.Ctx.logError(err)
			break
		}

		switch state {
		case 0:
			// Version 5
			if data == 0x05 {
				state = 1
				break
			}
			err = fmt.Errorf("invalid data(0) from: %s", ctx.Proxy.Host)
			state = 15
		case 1:
			// Authentication method
			if data == authType {
				state = 2
			} else {
				err = fmt.Errorf("authentication method not supported: %s", ctx.Proxy.Host)
				state = 15
				break
			}
			fallthrough
		case 2:
			// Send username and password (sub-negotiation is version 0x01)
			_, err = ctx.Remote.Writer.Write([]byte{0x01, byte(len(ctx.Proxy.Username))})
			if err != nil {
				state = 15
				break
			}
			_, err = ctx.Remote.Writer.Write([]byte(ctx.Proxy.Username))
			if err != nil {
				state = 15
				break
			}
			_, err = ctx.Remote.Writer.Write([]byte{byte(len(ctx.Proxy.Password))})
			if err != nil {
				state = 15
				break
			}
			_, err = ctx.Remote.Writer.Write([]byte(ctx.Proxy.Password))
			if err != nil {
				state = 15
				break
			}
			err = ctx.Remote.Writer.Flush()
			if err != nil {
				state = 15
				break
			}
			state = 3
		case 3:
			// Version 1 (sub-negotiation)
			if data == 0x01 {
				state = 4
				break
			}
			err = fmt.Errorf("invalid data(3) from: %s", ctx.Proxy.Host)
			state = 15
		case 4:
			// Authentication result
			if data == 0x00 {
				state = 5
			} else {
				err = fmt.Errorf("authentication failed: %s (%d)", ctx.Proxy.Host, data)
				state = 15
				break
			}
			fallthrough
		case 5:
			// Send connect command
			_, err = ctx.Remote.Writer.Write([]byte{0x05, 0x01})
			if err != nil {
				state = 15
				break
			}
			// Resend the original request info, but without the port
			_, err = ctx.Remote.Writer.Write(ctx.RequestData)
			if err != nil {
				state = 15
				break
			}
			// Add the port
			_, err = ctx.Remote.Writer.Write([]byte{byte((ctx.Remote.Port >> 8) & 0xFF), byte(ctx.Remote.Port & 0xFF)})
			if err != nil {
				state = 15
				break
			}
			err = ctx.Remote.Writer.Flush()
			if err != nil {
				state = 15
				break
			}
			state = 6
		case 6:
			// Version 5
			if data == 0x05 {
				state = 7
				break
			}
			err = fmt.Errorf("invalid data(6) from: %s", ctx.Proxy.Host)
			state = 15
		case 7:
			// Result code (0x00 = success)
			if data == 0x00 {
				state = 8
				break
			}
			err = fmt.Errorf("command failed: %d", data)
			state = 15
		case 8:
			// Reserved
			response = append(response, data)
			state = 9
		case 9:
			// IPv4 address
			response = append(response, data)
			if data == 0x01 {
				store = 4
				state = 10
			}
			// Domain name
			if data == 0x03 {
				store = 0
				state = 11
			}
			// IPv6
			if data == 0x04 {
				store = 16
				state = 13
			}
		case 10:
			// IPv4
			response = append(response, data)
			store--
			if store == 0 {
				store = 2
				state = 14
			}
		case 11:
			// Domain name length
			response = append(response, data)
			store = int(data)
			state = 12
		case 12:
			// Domain name
			response = append(response, data)
			store--
			if store == 0 {
				store = 2
				state = 14
			}
		case 13:
			// IPv6
			response = append(response, data)
			store--
			if store == 0 {
				store = 2
				state = 14
			}
		case 14:
			// Port
			response = append(response, data)
			store--
			if store == 0 {
				state = 15
			}
		}
	}
	if err == nil {
		// Respond with success (0x00)
		ctx.Client.Writer.Write([]byte{0x05, 0x00})
		// Send response from remote proxy
		ctx.Client.Writer.Write(response)
		ctx.Client.Writer.Flush()
	} else {
		// This hides the error from the remote proxy (by design)
		// Respond with general error (0x01)
		ctx.Client.Writer.Write([]byte{0x05, 0x01})
		ctx.Client.Writer.Write(ctx.RequestData)
		// Local port is undefined
		ctx.Client.Writer.Write([]byte{0x00, 0x00})
		ctx.Client.Writer.Flush()
		ctx.Ctx.logError(err)
		ctx.Remote.Connection.Close()
	}
	return err
}

// Background thread to process a client connection
func (ctx *ClientCtx) processClient() {
	defer ctx.Client.Connection.Close()
	// Client IO
	ctx.Client.Reader = bufio.NewReader(ctx.Client.Connection)
	ctx.Client.Writer = bufio.NewWriter(ctx.Client.Connection)

	// Process client request
	err := ctx.processInbound()
	if err != nil {
		if ctx.Ctx.Logger != nil {
			ctx.Ctx.Logger <- fmt.Sprintf(" [!] Invalid request from: %s (%s)\n", ctx.Client.Connection.RemoteAddr().String(), err.Error())
		}
		return
	}
	if ctx.Ctx.DomainFilter.Matches(ctx.Remote.Host) {
		if ctx.Ctx.Logger != nil {
			ctx.Ctx.Logger <- fmt.Sprintf(" [!] Blacklisted: %s\n", ctx.Remote.Host)
		}
		return
	}

	// Open a connection
	err = ctx.processOutbound()
	if err != nil {
		return
	}
	defer ctx.Remote.Connection.Close()

	// Create buffered IO reader/writers
	if ctx.Ctx.Logger != nil {
		if len(ctx.Proxy.Host) > 0 {
			ctx.Ctx.Logger <- fmt.Sprintf(" [+] Opened: [%s]:%d -> [%s]%s:%d\n", ctx.Client.Host, ctx.Client.Port, ctx.Proxy.Host, ctx.Remote.Host, ctx.Remote.Port)
		} else {
			ctx.Ctx.Logger <- fmt.Sprintf(" [+] Opened: [%s]:%d -> %s:%d\n", ctx.Client.Host, ctx.Client.Port, ctx.Remote.Host, ctx.Remote.Port)
		}
	}

	// Start threads to receive data from the client and remote connections
	var wait sync.WaitGroup
	wait.Add(2)
	go ctx.Client.CopyData(&ctx.Remote, &wait)
	go ctx.Remote.CopyData(&ctx.Client, &wait)

	// Wait for threads to finish
	wait.Wait()

	if ctx.Ctx.Logger != nil {
		if len(ctx.Proxy.Host) > 0 {
			ctx.Ctx.Logger <- fmt.Sprintf(" [-] Closed: [%s]:%d -> [%s]%s:%d (%v:%v bytes)\n", ctx.Client.Host, ctx.Client.Port, ctx.Proxy.Host, ctx.Remote.Host, ctx.Remote.Port, ctx.Client.ReadCount, ctx.Remote.ReadCount)
		} else {
			ctx.Ctx.Logger <- fmt.Sprintf(" [-] Closed: [%s]:%d -> %s:%d (%v:%v bytes)\n", ctx.Client.Host, ctx.Client.Port, ctx.Remote.Host, ctx.Remote.Port, ctx.Client.ReadCount, ctx.Remote.ReadCount)
		}
	}
}
