Let’s play this out as a scenario. We will look at two different paths: The Avalanche Effect (what happens to that MD5 hash if an error occurs) and The Interception (how a hacker interacts with it, and how TLS stops them).
------------------------------
## Scenario Part 1: The Avalanche Effect (Altering One Number)
Imagine your host device is sending the configuration over the network, but a brief spike of static on the line corrupts exactly one digit of data.
## What was sent:

SETTINGS MD5: f0f5df30e240af38dc4d9adc14cac504
listen-port              : 8081
port                     : 3333

## What the server actually receives:

listen-port              : 8081
port                     : 3334   <-- The last digit flipped from 3 to 4 due to network noise

## The Server's Reaction:
The server takes the corrupted text and runs it through the MD5 algorithm. Because of a property called the Avalanche Effect, changing just one tiny bit of input completely scrambles the output.

* Original MD5: f0f5df30e240af38dc4d9adc14cac504
* New Generated MD5: 4b8c92a10eef5547a112cd3914bab823 (completely different!)

The server compares the SETTINGS MD5 sent by the host (f0f5...) with the one it just calculated (4b8c...). They do not match. The server drops the file and flags an error: "Data corruption detected during transit."
------------------------------
## Scenario Part 2: The Interception (Why we need TLS)
Now, let's step up the stakes. Network noise didn't change the file. Instead, a malicious actor named Eve is sitting on the same local network, intercepting the traffic.
## The Vulnerability:
Because your host is sending this over a plain text connection, Eve can read everything clear as day. She sees your ports are 8081 and 3333.
Eve wants to hijack your traffic, so she deliberately changes the configuration file to route traffic to her own server on port 9999:

listen-port              : 8081
port                     : 9999   <-- Malicious change

Eve knows the server will check the MD5. So, she runs her new tampered text through her own MD5 calculator, gets the new hash, and swaps out the original header.
The server receives Eve's fake configuration and fake MD5. The hashes match perfectly, so the server blindly applies the malicious settings. MD5 failed to protect you because it only checks for accidents, not attacks.
------------------------------
## Scenario Part 3: Enter TLS (The Secure Solution)
To fix this, you decide to wrap the entire communication inside a TLS (Transport Layer Security) tunnel. Here is how the scenario changes:

   1. The Handshake: Before sending any data, the host and the server establish a secure TLS connection. The server presents its digital certificate (Authentication). The host verifies this certificate using public-key cryptography (RSA or ECDSA), proving it is talking to the real server, not Eve.
   2. The Key Exchange: They securely negotiate a temporary symmetric key.
   3. The Encryption: The host takes the entire configuration file and encrypts it using AES (Confidentiality). The plaintext ports disappear into complete gibberish.
   4. The Transmission: When Eve tries to intercept the data this time, all she sees is an unreadable stream of random characters. She cannot see the port numbers, and she cannot modify the text because TLS appends a secure HMAC to the packet. If she alters a single bit, the decryption fails on the server side instantly.


The visual architecture diagrams for each of the three scenarios, mapping out exactly how the data, hashes, and security mechanisms interact.
------------------------------
# Scenario 1: The Avalanche Effect (Accidental Corruption)
This diagram shows how a minor network glitch changes the text, causing the server to catch the error because the computed hash does not match the transmitted hash.

[ HOST DEVICE ]
  │
  ├── 1. Generates Config Text ────────────────────────┐
  │      "listen-port: 8018 \n port: 2222"             │
  │                                                    ▼
  ├── 2. Runs through MD5 Algorithm ───────► [ MD5: f0f5df30... ]
  │                                                    │
  ▼                                                    ▼
[ TRANSMISSION DATA: Plaintext Config + Original MD5 Hash ]
  │
  ▼  ⚡ (Network Static / Interference Flipped "2222" to "2224")
  │
[ RECEIVED DATA:   "listen-port: 8018 \n port: 2224" + Original MD5: f0f5df30... ]
  │                                  ▲
  │                                  │ (Extracted by Server)
  ▼                                  ▼
[ SERVER ] ──────────────────────────┼────────────────────────────────┐
  │                                  │                                │
  ├── 1. Takes Received Config Text ─┘                                │
  │                                                                   │
  ├── 2. Re-runs through MD5 ──────────────► [ MD5: 4b8c92a1... ]     │
  │                                                  │                │
  ▼                                                  ▼                │
  └── 3. Compares Hashes ──────► [ f0f5df30... ] vs [ 4b8c92a1... ]   │
                                           │                          │
                                           ▼                          │
                                    💥 MISMATCH!                     │
                                 (Config Rejected)                    │
──────────────────────────────────────────────────────────────────────┘

------------------------------
## Scenario 2: The Interception (Man-in-the-Middle Attack)
This diagram shows why MD5 alone cannot protect against human malice. Because the traffic is unencrypted, Eve can rewrite the data and forge a new matching hash.

[ HOST DEVICE ]
  │  Sends: Plaintext Config + MD5: f0f5df30... ("port: 2222")
  ▼
 [ UNENCRYPTED NETWORK PIPELINE ]
  │
  ▼ 🕵️‍♂️ (Intercepted by Eve)
[ EVE (ATTACKER) ] ──────────────────────────────────────────────────┐
  │                                                                   │
  ├── 1. Reads Plaintext Config Clear as Day                          │
  ├── 2. Changes port value to "9999"                                 │
  ├── 3. Computes Fake MD5 for new text ──► [ New MD5: a7c211e4... ]   │
  │                                                                   │
  ▼ Forwarded to Server ──────────────────────────────────────────────┘
  │
[ RECEIVED DATA:   "listen-port: 8018 \n port: 9999" + Fake MD5: a7c211e4... ]
  │
  ▼
[ SERVER ] ──────────────────────────────────────────────────────────┐
  │                                                                   │
  ├── 1. Re-runs Received Config ("9999") through MD5                  │
  │      Calculated Result ───────────────► [ MD5: a7c211e4... ]     │
  │                                                  │                │
  ▼                                                  ▼                │
  └── 2. Compares Hashes ──────► [ a7c211e4... ] vs [ a7c211e4... ]   │
                                           │                          │
                                           ▼                          │
                                     ✅ MATCH!                        │
                               (Malicious Config Applied)             │
──────────────────────────────────────────────────────────────────────┘

------------------------------
# Scenario 3: Enter TLS (Secure Tunnel Protection)
This diagram shows how TLS completely mitigates the attack. Eve can no longer read the data, forge a hash, or manipulate packets without breaking the cryptographic tunnel.

[ HOST DEVICE ]                                       [ SERVER ]
      │                                                   │
      ├────────────── 1. TLS Handshake ──────────────────►│ (Server Authenticates via RSA/DSA)
      │◄───────────── 2. Keys Exchanged ──────────────────┤ (Shared Session Keys Created)
      │                                                   │
      ▼                                                   ▼
===================== [ SECURE TLS ENCRYPTED TUNNEL ] =====================
      │                                                   │
   [ CONFIG ] ──► Encrypted with AES                      │
   [ HASH    ] ──► Signed with HMAC                        │
      │                                                   │
      ▼                                                   │
   [ Ciphertext Stream:  0x9F4A2C... ]                    │
      │                                                   │
      │   🕵️‍♂️ (Eve tries to intercept...)                   │
      │   Eve Sees: "0x9F4A2C..." (Garbage Data)           │
      │   Eve tries to alter a random byte anyway          │
      │                                                   │
      ▼                                                   ▼
   [ Tampered Ciphertext Stream ] ───────────────────────►│
                                                          │
                                                    [ DECRYPTION ENGINE ]
                                                          │ (Attempts decryption & HMAC verification)
                                                          ▼
                                                   💥 CRYPTO FAILURE! 
                                                  (Integrity/HMAC Broken)
                                                  (Session Terminated)
===========================================================================
