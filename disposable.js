'use strict';

var domainMap = {}
var arr = require('./domains')

for (var i = 0; i < arr.length; ++i)
    domainMap[arr[i]] = null

module.exports = {
    validate: function(domainOrEmail, callback) {
        var domain = domainOrEmail.split('@').pop()
        var isValid = !domainMap.hasOwnProperty(domain)

        if (!callback) {
            return isValid
        }
        callback(null, isValid)
    }
}
