package disposable

import (
	"io/ioutil"
	"strings"
)

const inFile = "domains.txt"

var domainMap = map[string]struct{}{}

func init() {
	dat, err := ioutil.ReadFile(inFile)
	if err != nil {
		panic("Missing (disposable email) domains file")
	}
	for _, domain := range strings.Split(string(dat), "\n") {
		domainMap[domain] = struct{}{}
	}
}

// Domain tests whether a string is among the known set of disposable mailboxes
func Domain(d string) bool {
	if _, ok := domainMap[d]; ok {
		return true
	}
	return false
}

// DomainMap returns all known domains in form of a map (for O(1)-ish search)
func DomainMap() map[string]struct{} {
	return domainMap
}
