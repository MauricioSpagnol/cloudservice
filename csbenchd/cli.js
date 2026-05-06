#!/usr/bin/env node
'use strict';

// ============================================================
// CS Coin Benchmark CLI (csbench-cli)
// Sends RPC commands to the running csbenchd daemon.
//
// Usage: csbench-cli [-testnet] <command> [params...]
//   getstatus [true]
//   getbenchmarks
//   getinfo
//   signfluxnodetransaction <txhex>
//   stop
// ============================================================

const http = require('http');

const MAINNET_PORT = 26225;
const TESTNET_PORT = 26235;

// Filter -testnet from args; let remaining args be command + params
const rawArgs   = process.argv.slice(2);
const isTestnet = rawArgs.includes('-testnet');
const args      = rawArgs.filter(a => a !== '-testnet');
const PORT      = isTestnet ? TESTNET_PORT : MAINNET_PORT;

const command = args[0];

if (!command) {
    process.stderr.write(
        'Usage: csbench-cli [-testnet] <command> [params]\n' +
        'Commands:\n' +
        '  getstatus [true]\n' +
        '  getbenchmarks\n' +
        '  getinfo\n' +
        '  signfluxnodetransaction <txhex>\n' +
        '  stop\n'
    );
    process.exit(1);
}

// Build RPC payload
let method = command;
let params = [];

switch (command) {
    case 'getstatus':
        params = args[1] === 'true' ? [true] : [];
        break;
    case 'signfluxnodetransaction':
        if (!args[1]) {
            process.stderr.write('signfluxnodetransaction requires a txhex argument\n');
            process.exit(1);
        }
        params = [args[1]];
        break;
    default:
        params = args.slice(1);
}

const body = JSON.stringify({ method, params });

const options = {
    hostname: '127.0.0.1',
    port:     PORT,
    method:   'POST',
    headers:  {
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(body),
    },
};

const req = http.request(options, (res) => {
    let data = '';
    res.on('data', chunk => { data += chunk; });
    res.on('end', () => {
        process.stdout.write(data + '\n');
    });
});

req.on('error', () => {
    // Daemon not reachable - return offline status for getstatus
    if (command === 'getstatus') {
        process.stdout.write(JSON.stringify({ status: 'offline' }) + '\n');
    } else {
        process.stdout.write(JSON.stringify({ error: 'Cannot connect to csbenchd on port ' + PORT }) + '\n');
    }
    process.exit(1);
});

req.write(body);
req.end();
