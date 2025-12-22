'use strict';

var domainMap = new Set();
var arr = require('./domains')

for (var i = 0; i < arr.length; ++i)
    domainMap.add([arr[i]])

module.exports = {
    validate: function(domainOrEmail, callback) {
        var domain = domainOrEmail.split('@').pop()
        var isValid = !domainMap.has(domain)

        if (!callback) {
            return isValid
        }
        callback(null, isValid)
    }
}
