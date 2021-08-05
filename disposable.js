'use strict';

const fs = require('fs');
const { execSync } = require('child_process')
const path = require('path');

const domainJson = path.join(__dirname, 'disposable.js');

let domainMap = {}

function shouldUpdateDomains() {
    const fileExists = fs.existsSync(domainJson);

    if (!fileExists) {
        return true;
    }

    const stat = fs.statSync(domainJson);

    if (stat.mtimeMs < (new Date().getTime() - 1000 * 60 * 60 * 24)) {
        return true;
    }

    return false;
}

function updateDomains() {
    try {
        execSync(path.join(__dirname, 'update.sh'))
    } catch (err) {
        console.error('Error updating domains')
        console.error(err.message)
    }
}

function loadDomains() {
    const arr = JSON.parse(fs.readFileSync(domainJson).toString());
    domainMap = {}

    for (let i = 0; i < arr.length; ++i)
        domainMap[arr[i]] = null
}

if (shouldUpdateDomains()) {
    updateDomains()
}

loadDomains()

module.exports = {
    validate: function (domainOrEmail, callback) {
        if (shouldUpdateDomains()) {
            updateDomains()
            loadDomains()
        }
        
        const domain = domainOrEmail.split('@').pop()
        const isValid = !domainMap.hasOwnProperty(domain)

        if (!callback) {
            return isValid
        }

        callback(null, isValid)
    }
}
