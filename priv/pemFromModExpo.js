var getPem = require('./node_modules/rsa-pem-from-mod-exp');

const modulus = process.argv[2];
const exponent = process.argv[3];

const pem = getPem(modulus, exponent);

console.log(pem);
