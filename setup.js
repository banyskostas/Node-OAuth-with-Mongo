'use strict';
const fs = require('fs');
fs.createReadStream('.sample-env')
    .pipe(fs.createWriteStream('.env'));

// Copy .sample-env to .env