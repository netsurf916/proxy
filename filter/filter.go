package filter

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

// DomainEntry for tracking each domain, rules, and hit count
type DomainEntry struct {
	Name string `json:"name"`
	Hits int    `json:"hits"`
}

// Matches a string against a domain name
func (entry *DomainEntry) Matches(item string) bool {
	// Check the length difference
	substr := len(item) - len(entry.Name)
	if substr < 0 {
		// If the passed in string is shorter, it won't possibly be a match
		return false
	}
	// Compare the overlap of item to the entry
	// This is an end comparision and not suitable for
	// things like IP addresses (which this filter doesn't
	// support).
	item = item[substr:]
	if strings.Compare(entry.Name, item) == 0 {
		return true
	}
	return false
}

// Filter struct containing a list of domains
type Filter struct {
	Domains  []DomainEntry
	FileName string
}

// Matches a string against all domain names in the filter
func (ctx *Filter) Matches(item string) bool {
	for _, domainEntry := range ctx.Domains {
		if domainEntry.Matches(strings.ToLower(item)) {
			domainEntry.Hits++
			return true
		}
	}
	return false
}

// LoadFile retrieves a domain list from a file
func (ctx *Filter) LoadFile(file string) bool {
	ctx.FileName = file
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
	err = json.Unmarshal(data, &ctx.Domains)
	if err != nil {
		return false
	}
	ctx.deduplicate()
	return true
}

// LoadListFile retrieves a list of URLs from a text file
func (ctx *Filter) LoadListFile(file string) (bool, int) {
	input, err := os.Open(file)
	temp := ""
	count := 0
	var list []string
	if err != nil {
		return false, count
	}
	defer input.Close()
	finfo, err := input.Stat()
	if err != nil {
		return false, count
	}
	data := make([]byte, finfo.Size())
	_, err = input.Read(data)
	if err != nil {
		return false, count
	}
	// Parse the result for lines of text
	for _, char := range data {
		if char != '\n' && char != '\r' {
			temp += string(char)
		} else {
			if len(temp) == 0 {
				continue
			}
			temp = strings.ToLower(temp)
			if len(temp) > 0 {
				list = append(list, temp)
				temp = ""
				count++
			}
		}
	}
	// Parse the individual lines
	for _, line := range list {
		// Skip empty lines
		if len(line) == 0 {
			continue
		}
		// Skip comments
		line = strings.ToLower(strings.Trim(line, " "))
		if line[0] == '#' {
			continue
		}
		// Take the last entry in case of something like "<IP> <domain>"
		elements := strings.Split(line, " ")
		if len(elements) > 1 {
			line = elements[len(elements)-1]
		}
		ctx.Domains = append(ctx.Domains, DomainEntry{line, 0})
	}
	ctx.deduplicate()
	return true, count
}

// SaveFile dumps all loaded URLs into a JSON formatted file
func (ctx *Filter) SaveFile(file string) bool {
	domains, err := json.MarshalIndent(ctx.Domains, "", " ")
	if err != nil {
		return false
	}
	output, err := os.Create(file)
	if err != nil {
		return false
	}
	_, err = output.Write(domains)
	if err != nil {
		return false
	}
	return true
}

// Save data to the same file it was loaded from (if available)
func (ctx *Filter) Save() {
	if len(ctx.FileName) > 0 {
		ctx.SaveFile(ctx.FileName)
	}
}

// LoadHTTP retrieves a domain list from a URL
func (ctx *Filter) LoadHTTP(url string) (bool, int) {
	resp, err := http.Get(url)
	temp := ""
	count := 0
	var list []string
	if err != nil {
		return false, count
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, count
	}
	// Parse the result for lines of text
	for _, char := range body {
		if char != '\n' && char != '\r' {
			temp += string(char)
		} else {
			if len(temp) == 0 {
				continue
			}
			temp = strings.ToLower(temp)
			if len(temp) > 0 {
				list = append(list, temp)
				temp = ""
				count++
			}
		}
	}
	// Parse the individual lines
	for _, line := range list {
		// Skip empty lines
		if len(line) == 0 {
			continue
		}
		// Skip comments
		line = strings.ToLower(strings.Trim(line, " "))
		if line[0] == '#' {
			continue
		}
		// Take the last entry in case of something like "<IP> <domain>"
		elements := strings.Split(line, " ")
		if len(elements) > 1 {
			line = elements[len(elements)-1]
		}
		ctx.Domains = append(ctx.Domains, DomainEntry{line, 0})
	}
	ctx.deduplicate()
	return true, count
}

func (ctx *Filter) deduplicate() {
	var newlist []DomainEntry
	for i, domainEntry := range ctx.Domains[:len(ctx.Domains)] {
		add := true
		for _, domainEntryCompare := range ctx.Domains[i+1:] {
			if domainEntry.Matches(domainEntryCompare.Name) {
				add = false
				break
			}
		}
		if add {
			newlist = append(newlist, domainEntry)
		}
	}
	ctx.Domains = newlist
}
