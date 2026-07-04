// Copyright (c) 2012-2014 The Bitcoin Core developers
// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VERSION_H
#define BITCOIN_VERSION_H

/**
 * network protocol versioning
 */

static const int PROTOCOL_VERSION = 170020;

//! initial proto version, to be increased after version/verack negotiation
static const int INIT_PROTO_VERSION = 209;

//! In this version, 'getheaders' was introduced.
static const int GETHEADERS_VERSION = 31800;

//! disconnect from peers older than this proto version
static const int MIN_PEER_PROTO_VERSION = 170002;

//! disconnect from peers older than this proto version
static const int MIN_PEER_PROTO_VERSION_TESTNET = 170016;

//! nTime field added to CAddress, starting with this version;
//! if possible, avoid requesting addresses nodes older than this
static const int CADDR_TIME_VERSION = 31402;

//! BIP 0031, pong message, is enabled for all versions AFTER this one
static const int BIP0031_VERSION = 60000;

//! "mempool" command, enhanced "getdata" behavior starts with this version
static const int MEMPOOL_GD_VERSION = 60002;

//! "filter*" commands are disabled without NODE_BLOOM after and including this version
static const int NO_BLOOM_VERSION = 170004;

//! protocol version that requires fluxnode payments
static const int MIN_PEER_PROTO_VERSION_FLUXNODE = 170009;

//! protocol version that means they support deterministic fluxnodes, not used as of now, usage of UPGRADE_KAMATA
static const int DETERMINISTIC_FLUXNODES = 170016;

static const int P2SH_NODES = 170019;

//! protocol version for UPGRADE_OPOI (chainparams.cpp) — see main.cpp's
//! per-epoch peer version check in ProcessMessage("version", ...): a node
//! disconnects any peer whose advertised version is below
//! vUpgrades[CurrentEpoch()].nProtocolVersion. PROTOCOL_VERSION above MUST be
//! >= the highest active upgrade's nProtocolVersion, or a node ends up
//! rejecting every peer (including another instance of itself) as soon as
//! that upgrade activates — this went unnoticed until the first real
//! multi-node test (F13-A, 2026-07-04): a lone regtest node never exercises
//! peer version negotiation, so it stayed invisible through the entire
//! OPoI implementation up to that point.
static const int OPOI_NODES = 170020;

#endif // BITCOIN_VERSION_H
