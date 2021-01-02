package main

import (
	"flag"
	"fmt"
	"net"
	"proxy/socks5"
	"strconv"
)

func logger(ctx socks5.Context) {
	for {
		line, ok := <-ctx.Logger
		if !ok {
			return
		}
		fmt.Print(line)
	}
}

func main() {
	// Process command line arguments
	addrPtr := flag.String("addr", "", "The local IP to bind to.")
	portPtr := flag.Int("port", 3128, "The port to listen on.")
	hostPtr := flag.String("host", "0.0.0.0", "Public address of the proxy (IP or hostname).")
	proxiesPtr := flag.String("proxies", "", "A JSON formatted file containing outbound proxies to use.")
	blacklistPtr := flag.String("blacklist", "blacklist.json", "Blacklist file to use (JSON formatted).")
	updatePtr := flag.Bool("update", false, "Pull new blacklist info from built-in URLS.")
	updatefromfilePtr := flag.String("updatefile", "", "File containing additional blacklist URLs to import.")
	updatefromURLPtr := flag.String("updateurl", "", "URL with additional blacklist URLs to import.")
	flag.Parse()

	// Socks5 context
	var Socks5Ctx socks5.Context

	// Determine which IP to use

	ips, err := net.LookupIP(*hostPtr)
	if err != nil {
		fmt.Printf(" [!] Unable to determine IP: %s\n", *hostPtr)
		return
	}
	Socks5Ctx.ReportIP = ips[0] // Select the first IP returned
	fmt.Printf(" [+] IP to report: %s\n", Socks5Ctx.ReportIP.String())

	// Create a channel for logging
	Socks5Ctx.Logger = make(chan string, 100)

	// Create a channel to transfer inbound connections
	Socks5Ctx.ClientConnections = make(chan socks5.ClientCtx, 10)

	// Setup connection string
	Socks5Ctx.ListenAddress = *addrPtr + ":" + strconv.Itoa(*portPtr)

	// Load list of outbound proxies to cycle between
	if len(*proxiesPtr) > 0 {
		if Socks5Ctx.Proxies.LoadFile(*proxiesPtr) {
			fmt.Printf(" [+] Loaded %d outbound proxies.\n", len(Socks5Ctx.Proxies.Hosts))
			fmt.Printf(" [+] IP will be reported from the remote proxy.\n")
		} else {
			fmt.Printf(" [!] Failed to load proxies from: %s\n", *proxiesPtr)
			fmt.Printf(" [+] Continuing to run without relay proxies.")
		}
	}

	// Initialize the filter (this makes it possible to specify a non-existent file and update)
	if !Socks5Ctx.DomainFilter.LoadFile(*blacklistPtr) || *updatePtr {
		// Load some external blacklists to create the initial list
		ExternalLists := []string{
			"https://winhelp2002.mvps.org/hosts.txt",
		}
		for _, s := range ExternalLists {
			ok, count := Socks5Ctx.DomainFilter.LoadHTTP(s)
			if ok {
				fmt.Printf(" [+] Loaded %d domains from: \"%s\"\n", count, s)
			} else {
				fmt.Printf(" [!] Error loading blacklist: \"%s\"\n", s)
			}
		}
	}
	if len(*updatefromfilePtr) > 0 {
		ok, count := Socks5Ctx.DomainFilter.LoadListFile(*updatefromfilePtr)
		if ok {
			fmt.Printf(" [+] Loaded %d domains from: \"%s\"\n", count, *updatefromfilePtr)
		} else {
			fmt.Printf(" [+] Error loading blacklist: \"%s\"\n", *updatefromfilePtr)
		}
	}
	if len(*updatefromURLPtr) > 0 {
		ok, count := Socks5Ctx.DomainFilter.LoadHTTP(*updatefromURLPtr)
		if ok {
			fmt.Printf(" [+] Loaded %d domains from: \"%s\"\n", count, *updatefromURLPtr)
		} else {
			fmt.Printf(" [+] Error loading blacklist: \"%s\"\n", *updatefromURLPtr)
		}
	}
	// Always write it back out to save changes (additions, deduplications, etc)
	Socks5Ctx.DomainFilter.SaveFile(*blacklistPtr)
	fmt.Printf(" [*] Blacklist contains %d domains\n", len(Socks5Ctx.DomainFilter.Domains))

	// Start a background thread to handle logging
	go logger(Socks5Ctx)

	// Start background thread to handle clients
	go Socks5Ctx.HandleClients()

	// Listen for inbound connections
	err = Socks5Ctx.Listen()
	if err != nil {
		fmt.Printf(" [!] %s\n", err.Error())
	}
}
