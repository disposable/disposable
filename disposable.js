'use strict';

const fs = require('fs');
const path = require('path');
const axios = require('axios');
const { resolve } = require('path');
const { rejects } = require('assert');

const domainJson = path.join(__dirname, 'domains.json');

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

async function updateDomains() {
    const stream = await axios.get(
        'https://raw.githubusercontent.com/disposable/disposable-email-domains/master/domains.json',
        { responseType: 'stream' });

    const file = fs.createWriteStream(domainJson);

    const end = new Promise(() => {
        file.on('close', resolve);
        file.on('error', (err) => {
            console.log('Error updating disposable emails: %s. %s', err.message, err.stack);
            rejects(err)
        })
    });

    stream.data.pipe(file);

    return end;
}

function loadDomains() {
    if (!fs.existsSync(domainJson)) {
        return;
    }
    let arr;
    try {
        const file = fs.readFileSync(domainJson).toString();
        arr = JSON.parse(file);
    } catch {
        updateDomains();
        return
    }
    domainMap = {}

    for (let i = 0; i < arr.length; ++i)
        domainMap[arr[i]] = null
}

if (shouldUpdateDomains()) {
    updateDomains()
}

loadDomains()


function validateSync(domainOrEmail) {

    if (!fs.existsSync(domainJson)) {
        return true;
    }

    const domain = domainOrEmail.split('@').pop()
    const isValid = !domainMap.hasOwnProperty(domain)

    return isValid;
}

async function _validate(domainOrEmail) {
    if (shouldUpdateDomains()) {
        await updateDomains()
        await loadDomains()
    }

    return validateSync(domainOrEmail);
}


module.exports = {
    validate: function (domainOrEmail, callback) {

        if (callback) {
            _validate(domainOrEmail).then(result => callback(null, result))
        }

        return validateSync(domainOrEmail);
    }
}
