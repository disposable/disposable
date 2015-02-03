// +build ignore
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
)

var sources = map[string][]string{
	"plain": []string{
		"https://gist.githubusercontent.com/adamloving/4401361/raw/66688cf8ad890433b917f3230f44489aa90b03b7",
		"https://gist.githubusercontent.com/michenriksen/8710649/raw/d42c080d62279b793f211f0caaffb22f1c980912"},
	"json": []string{
		"https://raw.githubusercontent.com/ivolo/disposable-email-domains/master/index.json"},
}

// Credit http://stackoverflow.com/a/106223/479736
const ValidHostnameRegex = `^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`

var r, _ = regexp.Compile(ValidHostnameRegex)

func stringIsValidHostname(a string) bool {
	return r.Match([]byte(a))
}

func main() {
	var domains = map[string]struct{}{}
	for _, typ := range []string{"plain", "json"} {
		for _, url := range sources[typ] {
			resp, err := http.Get(url)
			if err != nil {
				log.Fatalln("[fatal] Couldn't fetch this URL, you might wanna check it in a browser:\n---", url)
				return
			}
			defer resp.Body.Close()
			switch typ {
			case "plain":
				scnr := bufio.NewScanner(resp.Body)
				for scnr.Scan() {
					crt := scnr.Text()
					if !stringIsValidHostname(crt) {
						log.Println("[warning] [", url, "]\n--- Wrong input:", crt)
						continue
					}
					domains[crt] = struct{}{}
				}
				break
			case "json":
				buf := []string{}
				dec := json.NewDecoder(resp.Body)
				if err := dec.Decode(&buf); err != nil && err != io.EOF {
					log.Fatal(err)
				}
				for _, crt := range buf {
					domains[crt] = struct{}{}
				}
			}
		}
	}

	sorted := []string{}
	for k, _ := range domains {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	dottxt(sorted)
	dotjson(sorted)
	dotgo(sorted)
}

func dottxt(a []string) {
	f := fileHelper(".txt")
	defer f.Close()
	for _, v := range a {
		f.WriteString(v + "\n")
	}
}

func dotjson(a []string) {
	f := fileHelper(".json")
	defer f.Close()
	enc := json.NewEncoder(io.Writer(f))
	if err := enc.Encode(a); err != nil {
		log.Println("[warning] Couldn't encode to json")
	}
}

func dotgo(a []string) {
	f := fileHelper(".go")
	defer f.Close()
	f.WriteString(`package disposable

// Domains is a list of disposable email domains, stored as a map[string]struct{} for efficiency
var Domains = map[string]struct{} {
`)
	for _, v := range a {
		f.WriteString(fmt.Sprintf("\t\"%s\": struct{}{},\n", v))
	}
	f.WriteString("}")
}

func fileHelper(ext string) *os.File {
	name := "domains" + ext
	f, err := os.Create(name)
	if err != nil {
		log.Fatalln("[fatal] [", name, "] Can't open file")
		panic(err)
	}
	// Please defer f.Close()
	return f
}
