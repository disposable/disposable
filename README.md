## Disposable email domains

[![npm](https://badge.fury.io/js/disposable-email.svg)](https://www.npmjs.com/package/disposable-email)
[![GoDoc](https://godoc.org/github.com/andreis/disposable?status.svg)](https://godoc.org/github.com/andreis/disposable)

A collection of domains for disposable email services like [10MinuteMail](http://10minutemail.com) and [GuerrillaMail](https://www.guerrillamail.com). Also, some 🛠 to make your life easier.

### Why?

Use it to validate email addresses on sign up, or just to see how many real email addresses you have in your system.

### Usage

* list

A [file](https://raw.githubusercontent.com/andreis/disposable/master/domains.txt)
containing a sorted list of domains, one per line.

```
curl https://raw.githubusercontent.com/andreis/disposable/master/domains.txt
```

* JSON array

A [file](https://raw.githubusercontent.com/andreis/disposable/master/domains.json)
containing a sorted array of domains, in JSON format.

```
curl https://raw.githubusercontent.com/andreis/disposable/master/domains.json
```

* javascript

Install the npm package `disposable-email`. Validate synchronously or with a callback.

```lang=shell
npm i --save disposable-email
```

```lang=javascript
var disposable = require('disposable-email');

disposable.validate('gmail.com');
// true

disposable.validate('foo@gmail.com');
// true

disposable.validate('gmail.com', console.log);
// undefined
// null true
```

* Go

```lang=go
import "github.com/andreis/disposable"

if disposable.Domain("gmail.com") {
    panic("Uh oh!")
}
```

### Update the list of domains

To update the list of domains run `.generate` (requires `python3`), and optionally submit a PR.

```lang=bash
$ ./.generate
Fetched 1110 domains
 - 312 domain(s) added
 - 110 domain(s) removed
```

### Credits

-	https://github.com/adamloving
-	https://github.com/michenriksen
-	https://github.com/ivolo

### CDN

Production: https://rawcdn.githack.com/andreis/disposable/master/domains.json

Development: https://raw.githack.com/andreis/disposable/master/domains.json

by: https://raw.githack.com/
