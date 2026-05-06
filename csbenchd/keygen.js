#!/usr/bin/env node
'use strict';

// ============================================================
// CS Coin Benchmark Key Generator (csbench-keygen)
//
// Run ONCE to generate the CS Coin network benchmark keypair.
//
// The PRIVATE KEY is saved to ~/.csbenchmark/benchmark.key
// The PUBLIC KEY must be placed in src/chainparams.cpp
//   inside vecBenchmarkingPublicKeys.
//
// Distribute the private key file to all node operators
// through a secure channel.
// ============================================================

const EC     = require('elliptic').ec;
const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');
const os     = require('os');

const ec       = new EC('secp256k1');
const KEY_DIR  = path.join(os.homedir(), '.csbenchmark');
const KEY_FILE = path.join(KEY_DIR, 'benchmark.key');

function showPublicKey(privHex) {
    const kp     = ec.keyFromPrivate(privHex, 'hex');
    const pubHex = kp.getPublic(false, 'hex'); // uncompressed (04...)
    console.log('\n========================================================');
    console.log('  CS Coin Benchmark Key Info');
    console.log('========================================================');
    console.log('\nPRIVATE KEY file: ' + KEY_FILE);
    console.log('\nPUBLIC KEY (uncompressed, 130 hex chars):');
    console.log(pubHex);
    console.log('\nAdd to src/chainparams.cpp → vecBenchmarkingPublicKeys:');
    console.log('');
    console.log('    vecBenchmarkingPublicKeys.resize(1);');
    console.log(`    vecBenchmarkingPublicKeys[0] = std::make_pair("${pubHex}", 0);`);
    console.log('\n    assert(vecBenchmarkingPublicKeys.size() > 0);');
    console.log('\n========================================================\n');
}

// If key already exists, just display the public key
if (fs.existsSync(KEY_FILE)) {
    console.log('Key file already exists: ' + KEY_FILE);
    console.log('(Delete it if you want to regenerate — WARNING: this breaks existing nodes)');
    const privHex = fs.readFileSync(KEY_FILE, 'utf8').trim();
    showPublicKey(privHex);
    process.exit(0);
}

// Generate new keypair using cryptographically secure random bytes
const privBytes = crypto.randomBytes(32);
const privHex   = privBytes.toString('hex');

// Validate via elliptic (ensures key is in valid range)
ec.keyFromPrivate(privHex, 'hex');

// Save with restricted permissions
if (!fs.existsSync(KEY_DIR)) {
    fs.mkdirSync(KEY_DIR, { recursive: true, mode: 0o700 });
}
fs.writeFileSync(KEY_FILE, privHex, { mode: 0o600 });

console.log('Keypair generated successfully!');
showPublicKey(privHex);

console.log('NEXT STEPS:');
console.log('  1. Copy the vecBenchmarkingPublicKeys line above into src/chainparams.cpp');
console.log('     (replace ALL existing entries in the mainnet section)');
console.log('  2. Rebuild the CS Coin daemon');
console.log('  3. Distribute ~/.csbenchmark/benchmark.key to node operators securely');
console.log('  4. Run: npm install && node daemon.js\n');
