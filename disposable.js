'use strict';

var domainMap = {};
for (let d of require('./domains')) {
    domainMap[d] = null;
}

module.exports = {
    validate: (domain, callback) => {
        if (!callback) {
            return !domainMap.hasOwnProperty(domain);
        }
        callback(null, !domainMap.hasOwnProperty(domain));
    }
}
