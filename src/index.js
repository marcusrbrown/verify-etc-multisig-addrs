#!/usr/bin/env node
'use strict'; // eslint-disable-line

import fs from 'fs';
import csv from 'fast-csv';
import request from 'request';
import kbpgp from 'kbpgp';

const NAME_COLUMN = 'Name';
const URL_COLUMN = 'Pub Key URL';
const ADDRESS_COLUMN = 'ETC Multisig Address';
const SIGNATURE_COLUMN = 'ETC Multisig Address Signature';

const keyRing = new kbpgp.keyring.KeyRing();

const transformRow = (row, next) => {
  const url = row[URL_COLUMN];
  request(url, (error, response, body) => {
    if (!error && response.statusCode === 200) {
      if (!response.headers['content-type'].startsWith('text/plain')) {
        next(new Error(`Content-Type must be "text/plain" at ${url}`));
      } else {
        kbpgp.KeyManager.import_from_armored_pgp({
          armored: body,
        }, (keyError, key) => {
          if (keyError) {
            next(keyError);
          } else {
            const name = row[NAME_COLUMN];
            const address = row[ADDRESS_COLUMN];
            const armored = row[SIGNATURE_COLUMN];
            keyRing.add_key_manager(key);
            next(null, { name, address, armored });
          }
        });
      }
    } else {
      next(error || new Error(`Server responded with ${response.statusCode} at ${url}`));
    }
  });
};

const validateRow = (row, next) => {
  const { name, address, armored } = row;
  kbpgp.unbox({
    keyfetch: keyRing,
    armored
  }, (err, literals) => {
    if (err) {
      next(err);
    } else if (!literals.length) {
      next(new Error(`No literals available from '${name}'`));
    } else {
      const literal = literals[0];
      const message = literal.toString();
      if (!literal.get_data_signer()) {
        next(new Error(`Message from '${name}' is not signed`));
      } else {
        row.message = message;
        next(null, address === message);
      }
    }
  });
};

let totalRows = 0;
let verifiedRows = 0;

fs.createReadStream('./multisig-addresses.csv')
  .pipe(csv({
    headers: true,
    strictColumnHandling: true
  }))
  .transform(transformRow)
  .validate(validateRow)
  .on('data-invalid', (row) => {
    const { name, address, message } = row;
    console.error(`The address ${address} for '${name}' does not match the signed message '${message}'.`);
    totalRows += 1;
  })
  .on('readable', function () {
    let row = this.read();
    while (row) {
      const { name, address } = row;
      console.log(`Verified signed address ${address} from '${name}'.`);
      totalRows += 1;
      verifiedRows += 1;
      row = this.read();
    }
  })
  .on('end', () => {
    if (totalRows !== verifiedRows) {
      console.error(`${totalRows - verifiedRows} could not be verified.`);
    } else {
      console.log(`Verified a total of ${totalRows} addresses`);
    }
  })
  .on('error', err => {
    console.error(`${err}\nAborting.`);
    process.exit(255);
  });
