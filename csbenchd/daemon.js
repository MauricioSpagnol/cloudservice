#!/usr/bin/env node
'use strict';

// ============================================================
// CS Coin Benchmark Daemon (csbenchd)
// Validates node hardware and signs confirmation transactions.
// Communicates via HTTP RPC on 0.0.0.0:26225 (mainnet)
//                                or 0.0.0.0:26235 (testnet)
// ============================================================

const http     = require('http');
const { spawn } = require('child_process');
const fs       = require('fs');
const path     = require('path');
const crypto   = require('crypto');
const os       = require('os');
const EC       = require('elliptic').ec;

const ec = new EC('secp256k1');

// ---- Configuration --------------------------------------------------
const VERSION             = '1.0.0';
const MAINNET_PORT        = 26225;
const TESTNET_PORT        = 26235;
const KEY_DIR             = path.join(os.homedir(), '.csbenchmark');
const KEY_FILE            = path.join(KEY_DIR, 'benchmark.key');
const LOG_FILE            = path.join(KEY_DIR, 'debug.log');
const BENCH_SCRIPT        = path.join(__dirname, 'hardwarebench.sh');
const BENCHMARK_INTERVAL  = 12 * 60 * 60 * 1000; // 12 h

const isTestnet = process.argv.includes('-testnet');
const PORT      = isTestnet ? TESTNET_PORT : MAINNET_PORT;

// ---- Tier mapping ---------------------------------------------------
// Must match enum Tier in src/fluxnode/fluxnode.h
const TIER_STRING_TO_INT = { CUMULUS: 1, NIMBUS: 2, STRATUS: 3, THUNDER: 4 };
const TIER_INT_TO_STRING = { 1: 'CUMULUS', 2: 'NIMBUS', 3: 'STRATUS', 4: 'THUNDER' };

// ---- TX constants ---------------------------------------------------
// Must match src/primitives/transaction.h
const FLUXNODE_TX_VERSION            = 5;
const FLUXNODE_TX_UPGRADEABLE_VERSION = 6;
const FLUXNODE_CONFIRM_TX_TYPE       = 4; // 1 << 2

// ---- Message signing magic ------------------------------------------
// Must match src/main.cpp: strMessageMagic
const MESSAGE_MAGIC = 'CS Coin Signed Message:\n';

// ---- Global state ---------------------------------------------------
let privateKey      = null;   // hex string
let benchmarkResult = null;   // parsed result object
let benchmarkStatus = 'running'; // 'running' | 'complete' | 'failed'
let httpServer      = null;

// ---- Logging --------------------------------------------------------
function log(msg) {
    const line = `${new Date().toISOString()} ${msg}\n`;
    process.stdout.write(line);
    try { fs.appendFileSync(LOG_FILE, line); } catch (_) {}
}

// ---- Key management -------------------------------------------------
function loadKey() {
    if (!fs.existsSync(KEY_DIR)) {
        fs.mkdirSync(KEY_DIR, { recursive: true, mode: 0o700 });
    }

    if (!fs.existsSync(KEY_FILE)) {
        log('ERROR: No private key found. Run: node keygen.js');
        process.exit(1);
    }

    const privHex = fs.readFileSync(KEY_FILE, 'utf8').trim();
    if (!/^[0-9a-fA-F]{64}$/.test(privHex)) {
        log('ERROR: Invalid private key format in ' + KEY_FILE);
        process.exit(1);
    }

    const kp = ec.keyFromPrivate(privHex, 'hex');
    log('Public key (uncompressed): ' + kp.getPublic(false, 'hex'));
    return privHex;
}

// ---- Bitcoin-style compact-size serialization -----------------------
function writeCompactSize(n) {
    if (n < 0xfd) {
        return Buffer.from([n]);
    }
    if (n <= 0xffff) {
        const b = Buffer.alloc(3);
        b[0] = 0xfd;
        b.writeUInt16LE(n, 1);
        return b;
    }
    if (n <= 0xffffffff) {
        const b = Buffer.alloc(5);
        b[0] = 0xfe;
        b.writeUInt32LE(n, 1);
        return b;
    }
    throw new Error('CompactSize value too large');
}

function readCompactSize(buf, pos) {
    const b = buf[pos];
    if (b < 0xfd) return { value: b, size: 1 };
    if (b === 0xfd) return { value: buf.readUInt16LE(pos + 1), size: 3 };
    if (b === 0xfe) return { value: buf.readUInt32LE(pos + 1), size: 5 };
    throw new Error('CompactSize 8-byte not supported');
}

// ---- Bitcoin-style message hashing ----------------------------------
// Matches CHashWriter used in CObfuScationSigner::SignMessage /
// VerifyMessage (src/fluxnode/obfuscation.cpp)
function magicHash(message) {
    const magicBuf = Buffer.from(MESSAGE_MAGIC, 'utf8');
    // message may contain raw binary bytes (from sig vector)
    const msgBuf = Buffer.from(message, 'binary');

    const payload = Buffer.concat([
        writeCompactSize(magicBuf.length), magicBuf,
        writeCompactSize(msgBuf.length),   msgBuf,
    ]);

    const first  = crypto.createHash('sha256').update(payload).digest();
    return crypto.createHash('sha256').update(first).digest();
}

// ---- Signing --------------------------------------------------------
// Produces a 65-byte compact recoverable signature.
// Byte 0 = 27 + recoveryParam  (uncompressed key, no +4)
// This matches CKey::SignCompact in src/key.cpp with fCompressed=false
function signMessage(message, privKeyHex) {
    const hash = magicHash(message);
    const key  = ec.keyFromPrivate(privKeyHex, 'hex');
    const sig  = key.sign(hash);

    const rBuf  = sig.r.toArrayLike(Buffer, 'be', 32);
    const sBuf  = sig.s.toArrayLike(Buffer, 'be', 32);
    const recId = sig.recoveryParam; // 0 or 1

    // Uncompressed key flag: 27 + recId  (no +4 for compressed)
    return Buffer.concat([Buffer.from([27 + recId]), rBuf, sBuf]);
}

// ---- Transaction parsing/building -----------------------------------
// Handles FLUXNODE_TX_VERSION (5) and FLUXNODE_TX_UPGRADEABLE_VERSION (6)
// for FLUXNODE_CONFIRM_TX_TYPE (4).
//
// Wire format for CONFIRM (SER_NETWORK):
//   header(4) nType(1) collateralIn(36) sigTime(4) benchmarkTier(1)
//   benchmarkSigTime(4) nUpdateType(1) ip(varstr)
//   sig(varvec) benchmarkSig(varvec)

function parseTx(hexStr) {
    const buf = Buffer.from(hexStr, 'hex');
    let pos = 0;

    // 4-byte header: bit31 = fOverwintered, bits[30:0] = nVersion
    const header       = buf.readUInt32LE(pos); pos += 4;
    const fOverwintered = (header >>> 31) === 1;
    const version      = header & 0x7fffffff;

    if (version !== FLUXNODE_TX_VERSION && version !== FLUXNODE_TX_UPGRADEABLE_VERSION) {
        throw new Error(`Unsupported tx version: ${version}`);
    }

    const nType = buf.readInt8(pos); pos += 1;
    if (nType !== FLUXNODE_CONFIRM_TX_TYPE) {
        throw new Error(`Expected CONFIRM tx type (${FLUXNODE_CONFIRM_TX_TYPE}), got: ${nType}`);
    }

    // COutPoint: txhash(32 LE) + n(uint32 LE)
    const collateralHash = buf.slice(pos, pos + 32); pos += 32;
    const collateralN    = buf.readUInt32LE(pos);    pos += 4;

    const sigTime        = buf.readUInt32LE(pos); pos += 4;
    const benchmarkTier  = buf.readInt8(pos);     pos += 1;
    const benchmarkSigTime = buf.readUInt32LE(pos); pos += 4;
    const nUpdateType    = buf.readInt8(pos);     pos += 1;

    // ip: varstring
    const ipCs  = readCompactSize(buf, pos); pos += ipCs.size;
    const ip    = buf.slice(pos, pos + ipCs.value).toString('utf8');
    pos += ipCs.value;

    // sig: varvector (node operator signature - already set)
    const sigCs = readCompactSize(buf, pos); pos += sigCs.size;
    const sig   = buf.slice(pos, pos + sigCs.value);
    pos += sigCs.value;

    // benchmarkSig: varvector (empty on input, we will fill it)
    const bsCs         = readCompactSize(buf, pos); pos += bsCs.size;
    const benchmarkSig = buf.slice(pos, pos + bsCs.value);
    pos += bsCs.value;

    return {
        version, fOverwintered,
        nType, collateralHash, collateralN,
        sigTime, benchmarkTier, benchmarkSigTime,
        nUpdateType, ip, sig, benchmarkSig,
    };
}

function buildTx(tx) {
    const parts = [];

    // header
    const headerVal = (tx.fOverwintered ? 0x80000000 : 0) | (tx.version & 0x7fffffff);
    const hBuf = Buffer.alloc(4);
    hBuf.writeUInt32LE(headerVal >>> 0);
    parts.push(hBuf);

    // nType
    const tBuf = Buffer.alloc(1); tBuf.writeInt8(tx.nType); parts.push(tBuf);

    // collateralIn
    parts.push(tx.collateralHash);
    const nBuf = Buffer.alloc(4); nBuf.writeUInt32LE(tx.collateralN); parts.push(nBuf);

    // sigTime
    const stBuf = Buffer.alloc(4); stBuf.writeUInt32LE(tx.sigTime); parts.push(stBuf);

    // benchmarkTier
    const btBuf = Buffer.alloc(1); btBuf.writeInt8(tx.benchmarkTier); parts.push(btBuf);

    // benchmarkSigTime
    const bstBuf = Buffer.alloc(4); bstBuf.writeUInt32LE(tx.benchmarkSigTime); parts.push(bstBuf);

    // nUpdateType
    const utBuf = Buffer.alloc(1); utBuf.writeInt8(tx.nUpdateType); parts.push(utBuf);

    // ip (varstring)
    const ipBuf = Buffer.from(tx.ip, 'utf8');
    parts.push(writeCompactSize(ipBuf.length));
    parts.push(ipBuf);

    // sig (varvector)
    parts.push(writeCompactSize(tx.sig.length));
    parts.push(tx.sig);

    // benchmarkSig (varvector)
    parts.push(writeCompactSize(tx.benchmarkSig.length));
    parts.push(tx.benchmarkSig);

    return Buffer.concat(parts);
}

// ---- Hardware benchmark runner --------------------------------------
function runBenchmark() {
    benchmarkStatus = 'running';
    log('Starting hardware benchmark (this may take several minutes)...');

    if (!fs.existsSync(BENCH_SCRIPT)) {
        log('ERROR: hardwarebench.sh not found at ' + BENCH_SCRIPT);
        benchmarkStatus = 'failed';
        benchmarkResult = { tier: 'FAILED', tierInt: 0, timestamp: nowUnix() };
        return;
    }

    const proc = spawn('bash', [BENCH_SCRIPT], { timeout: 600000 });
    let output = '';

    proc.stdout.on('data', d => { output += d.toString(); });
    proc.stderr.on('data', d => { output += d.toString(); });

    proc.on('close', (code) => {
        // Strip ANSI colour codes before parsing
        const clean = output.replace(/\x1B\[[0-9;]*m/g, '');
        log('Benchmark raw output:\n' + clean);

        const match = (re) => { const m = clean.match(re); return m ? m[1] : null; };

        const tierStr      = match(/\| Benchmark:\s+(CUMULUS|NIMBUS|STRATUS|THUNDER|FAILED)/);
        const ram          = parseInt(match(/\| RAM:\s+([0-9]+)/)  || '0');
        const vcores       = parseInt(match(/\| CPU vcores:\s+([0-9]+)/) || '0');
        const eps          = parseFloat(match(/\| EPS:\s+([0-9.]+)/) || '0');
        const ssd          = parseInt(match(/\| SSD:\s+([0-9]+)/)  || '0');
        const hdd          = parseInt(match(/\| HDD:\s+([0-9]+)/)  || '0');
        const writespeed   = parseInt(match(/\| WRITESPEED:\s+([0-9]+)/) || '0');

        const tier = tierStr || 'FAILED';

        benchmarkResult = {
            tier,
            tierInt:    TIER_STRING_TO_INT[tier] || 0,
            ram, vcores, eps, ssd, hdd, writespeed,
            timestamp:  nowUnix(),
        };

        benchmarkStatus = (tier !== 'FAILED') ? 'complete' : 'failed';
        log(`Benchmark finished: tier=${tier} ssd=${ssd} eps=${eps}`);
    });

    proc.on('error', (err) => {
        log('Benchmark process error: ' + err.message);
        benchmarkStatus = 'failed';
        benchmarkResult = { tier: 'FAILED', tierInt: 0, timestamp: nowUnix() };
    });
}

function nowUnix() { return Math.floor(Date.now() / 1000); }

// ---- RPC handlers ---------------------------------------------------
function rpcGetstatus(params) {
    const detailed = params && params[0] === true;
    const resp = { status: 'online', benchmarkStatus, version: VERSION };
    if (detailed && benchmarkResult) resp.benchmarks = benchmarkResult;
    return resp;
}

function rpcGetbenchmarks() {
    if (!benchmarkResult) return { error: 'Benchmark not yet complete, please wait.' };
    return benchmarkResult;
}

function rpcGetinfo() {
    return {
        version: VERSION,
        benchmarkStatus,
        tier: benchmarkResult ? benchmarkResult.tier : 'NONE',
    };
}

function rpcSignTransaction(params) {
    const txHex = params && params[0];
    if (!txHex) {
        return { status: 'error', error: 'No transaction hex provided' };
    }

    if (benchmarkStatus === 'running') {
        return { status: 'running', error: 'Benchmark still running, please wait.' };
    }

    if (benchmarkStatus === 'failed' || !benchmarkResult || benchmarkResult.tierInt === 0) {
        return { status: 'failed', error: 'Hardware benchmark failed. Node does not meet minimum requirements.' };
    }

    try {
        const tx       = parseTx(txHex);
        const tierInt  = benchmarkResult.tierInt;
        const sigTime  = nowUnix();

        // Message = raw_sig_bytes_as_latin1_string + tier_decimal + sigtime_decimal + ip
        // Matches: std::string(tx.sig.begin(), tx.sig.end()) + to_string(tier) + to_string(time) + ip
        const message  = tx.sig.toString('binary') + String(tierInt) + String(sigTime) + tx.ip;

        const benchmarkSig = signMessage(message, privateKey);

        tx.benchmarkTier    = tierInt;
        tx.benchmarkSigTime = sigTime;
        tx.benchmarkSig     = benchmarkSig;

        const signedHex = buildTx(tx).toString('hex');

        log(`Signed tx for ip=${tx.ip} tier=${TIER_INT_TO_STRING[tierInt]}`);

        return {
            status:  'complete',
            tier:    benchmarkResult.tier,
            tierInt,
            hex:     signedHex,
        };
    } catch (err) {
        log('signfluxnodetransaction error: ' + err.message);
        return { status: 'error', error: err.message };
    }
}

function rpcStop() {
    log('Stop command received, shutting down...');
    if (httpServer) {
        httpServer.close(() => process.exit(0));
        setTimeout(() => process.exit(0), 2000);
    } else {
        process.exit(0);
    }
    return { status: 'stopping' };
}

// ---- HTTP RPC server ------------------------------------------------
function startServer() {
    httpServer = http.createServer((req, res) => {
        if (req.method !== 'POST') {
            res.writeHead(405); res.end(); return;
        }

        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
            let result;
            try {
                const { method, params } = JSON.parse(body);
                log('RPC call: ' + method);

                switch (method) {
                    case 'getstatus':
                        result = rpcGetstatus(params); break;
                    case 'getbenchmarks':
                        result = rpcGetbenchmarks(); break;
                    case 'getinfo':
                        result = rpcGetinfo(); break;
                    case 'signfluxnodetransaction':
                        result = rpcSignTransaction(params); break;
                    case 'stop':
                        result = rpcStop(); break;
                    default:
                        result = { error: 'Unknown method: ' + method };
                }
            } catch (err) {
                result = { error: 'Parse error: ' + err.message };
            }

            const json = JSON.stringify(result);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(json);
        });
    });

    httpServer.listen(PORT, '0.0.0.0', () => {
        log(`CS Coin Benchmark Daemon v${VERSION} listening on 0.0.0.0:${PORT}${isTestnet ? ' (testnet)' : ''}`);
    });

    httpServer.on('error', (err) => {
        if (err.code === 'EADDRINUSE') {
            log(`ERROR: Port ${PORT} already in use. Is csbenchd already running?`);
        } else {
            log('Server error: ' + err.message);
        }
        process.exit(1);
    });
}

// ---- Entry point ----------------------------------------------------
function main() {
    log('CS Coin Benchmark Daemon starting...');

    // Ensure log dir exists
    if (!fs.existsSync(KEY_DIR)) {
        fs.mkdirSync(KEY_DIR, { recursive: true, mode: 0o700 });
    }

    privateKey = loadKey();

    startServer();

    // Run benchmark shortly after server is ready, then every 12 h
    setTimeout(() => {
        runBenchmark();
        setInterval(runBenchmark, BENCHMARK_INTERVAL);
    }, 2000);

    process.on('SIGTERM', () => { log('SIGTERM'); process.exit(0); });
    process.on('SIGINT',  () => { log('SIGINT');  process.exit(0); });
}

main();
