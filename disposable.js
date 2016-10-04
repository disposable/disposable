'use strict';

var domainMap = {}
var arr = require('./domains.json')

for (var i = 0; i < arr.length; ++i)
    domainMap[arr[i]] = null

module.exports = {
    validate: function(domain, callback) {
        if (!callback) {
            return !domainMap.hasOwnProperty(domain)
        }
        callback(null, !domainMap.hasOwnProperty(domain))
    }
}
