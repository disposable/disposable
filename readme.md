# Disposable

## Usage

### Use it in your Go code

```lang=go
import "github.com/lavab/disposable"

if _, ok := disposable.Domains[strings.ToLower(aDomain)]; ok {
   log.Println("Domain", aDomain, "is not reliable, sorry.")
   panic("Why not panic?")
}
```

### Get a plaintext or json file

Curling is fun:

```lang=shell
# One domain per line
curl https://raw.githubusercontent.com/lavab/disposable/master/domains.txt
# A JSON array
curl https://raw.githubusercontent.com/lavab/disposable/master/domains.json
```
You can just download the files ([txt](https://raw.githubusercontent.com/lavab/disposable/master/domains.txt) or [json](https://raw.githubusercontent.com/lavab/disposable/master/domains.json)).

### Run the generator

`disposable` comes batteries-included. You can run `.generate/generate.go` to get a
more up-to-date list of domains. However, some links might be dead. PRs are appreciated.

```lang=shell
go get -u github.com/lavab/disposable
cd $GOHOME/src/github.com/lavab/disposable
go run .generate/generate.go
```

## Credit

* https://gist.github.com/adamloving/4401361
* https://gist.github.com/michenriksen/8710649
* https://github.com/ivolo/disposable-email-domains

## Andrei's recommendations

I recommend these services, they're fast and have good, non-spammy UI:

* http://10minutemail.com (one of the few sites for which I disable uBlock)
* https://www.guerrillamail.com (https)
