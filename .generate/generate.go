// +build ignore

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
)

const filename = "domains"
const ignoreFilename = "ignorelist"
const banlistFilename = "banlist"

func main() {
	var domains = fetchDomains(map[string][]string{
		"plain": []string{
			"https://gist.githubusercontent.com/adamloving/4401361/raw/66688cf8ad890433b917f3230f44489aa90b03b7",
			"https://gist.githubusercontent.com/michenriksen/8710649/raw/d42c080d62279b793f211f0caaffb22f1c980912",
			"https://raw.githubusercontent.com/wesbos/burner-email-providers/7f3c191e876790b7a01b053a8319a59183037993/emails.txt"},
		"json": []string{
			"https://raw.githubusercontent.com/ivolo/disposable-email-domains/master/index.json"},
	})

	domains = addAndRemoveEntries(domains,
		readStringArrayFromFile(banlistFilename),
		readStringArrayFromFile(ignoreFilename))
	sort.Strings(domains)

	added, removed := twoWayDelta(domains, readJSONArrayFromFile(filename+".json"))
	log.Println("== Added", len(added), "domains.")
	for i, dom := range added {
		log.Printf("%3d\t%s\n", i+1, dom)
	}
	log.Println("== Removed", len(removed), "domains.")
	for i, dom := range removed {
		log.Printf("%3d\t%s\n", i+1, dom)
	}

	dottxt(domains)
	dotjson(domains)
	dotgo(domains)
}

func dottxt(a []string) {
	f := fileHelper(".txt")
	defer f.Close()
	f.WriteString(strings.Join(a, "\n"))
}

func dotjson(a []string) {
	f := fileHelper(".json")
	defer f.Close()
	enc := json.NewEncoder(io.Writer(f))
	if err := enc.Encode(a); err != nil {
		log.Fatalln("Couldn't encode to json!")
	}
}

func dotgo(a []string) {
	f := fileHelper(".go")
	defer f.Close()
	out := "package disposable\n\n"
	out += "// Domain tests whether a string is among the known set of disposable mailboxes\n"
	out += "func Domain(d string) bool {\n"
	out += "\tif _, ok := domains[d]; ok {\n"
	out += "\t\treturn true\n"
	out += "\t}\n"
	out += "\treturn false\n"
	out += "}\n\n"
	out += "// domains is a map where keys are known domain names for temporary mailboxes\n"
	out += "var domains = map[string]struct{} {\n"
	lenMax := 1
	for _, v := range a {
		if len(v) > lenMax {
			lenMax = len(v)
		}
	}
	for _, v := range a {
		out += fmt.Sprintf("\t\"%s\":%s struct{}{},\n", v, strings.Repeat(" ", lenMax-len(v)))
	}
	out += "}\n"
	f.WriteString(out)
}

func fileHelper(ext string) *os.File {
	name := filename + ext
	f, err := os.Create(name)
	if err != nil {
		log.Fatalln("[fatal] [", name, "] Can't open file")
		panic(err)
	}
	// Please defer f.Close()
	return f
}

func readJSONArrayFromFile(filename string) []string {
	out := []string{}
	file, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Printf("Couldn't read %s\n", filename)
		return []string{}
	}
	err = json.Unmarshal(file, &out)
	if err != nil {
		log.Printf("Couldn't unmarshal %s, check if the file contains a JSON array", filename)
		return []string{}
	}
	return out
}

func readStringArrayFromFile(filename string) []string {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Printf("Couldn't read %s", filename)
	}
	return strings.Split(string(content), "\n")
}

func fetchDomains(sources map[string][]string) []string {
	out := []string{}
	for _, typ := range []string{"plain", "json"} {
		for _, url := range sources[typ] {
			resp, err := http.Get(url)
			if err != nil {
				log.Fatalln("[fatal] Couldn't fetch this URL, you might wanna check it in a browser:\n---", url)
			}
			defer resp.Body.Close()
			switch typ {
			case "plain":
				scnr := bufio.NewScanner(resp.Body)
				for scnr.Scan() {
					crt := scnr.Text()
					if !stringIsValidHostname(crt) {
						log.Printf("Error in %s\n%s'%s' is not a valid hostname\n",
							url, strings.Repeat(" ", 20), crt)
						continue
					}
					out = append(out, strings.ToLower(crt))
				}
				break
			case "json":
				buf := []string{}
				dec := json.NewDecoder(resp.Body)
				if err := dec.Decode(&buf); err != nil && err != io.EOF {
					log.Fatal(err)
				}
				for _, crt := range buf {
					out = append(out, strings.ToLower(crt))
				}
			}
		}
	}
	return out
}

// twoWayDelta returns two arrays: a \ b, and b \ a
func twoWayDelta(a, b []string) ([]string, []string) {
	deltaa, deltab := []string{}, []string{}
	dicta, dictb := map[string]bool{}, map[string]bool{}
	for _, item := range a {
		dicta[item] = true
	}
	for _, item := range b {
		dictb[item] = true
	}

	for k := range dicta {
		if _, ok := dictb[k]; ok {
			dicta[k], dictb[k] = false, false
		}
	}
	for k, v := range dicta {
		if v {
			deltaa = append(deltaa, k)
		}
	}
	for k, v := range dictb {
		if v {
			deltab = append(deltab, k)
		}
	}
	return deltaa, deltab
}

// addAndRemoveEntries takes three arrays and returns (1 U 2 \ 3)
func addAndRemoveEntries(arr, add, rm []string) []string {
	lookup := map[string]struct{}{}
	for _, item := range append(arr, add...) {
		lookup[item] = struct{}{}
	}
	for _, item := range rm {
		delete(lookup, item)
	}
	out := make([]string, len(lookup))
	i := 0
	for k := range lookup {
		out[i] = k
		i++
	}
	return out
}

// Credit http://stackoverflow.com/a/106223/479736
const ValidHostnameRegex = `^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`

var r, _ = regexp.Compile(ValidHostnameRegex)

func stringIsValidHostname(a string) bool {
	return r.Match([]byte(a))
}
