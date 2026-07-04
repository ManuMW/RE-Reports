# Inside a Supply Chain Attack: Technical Analysis of a Node.js InfoStealer

* **Date:** July 4, 2026
* **Category:** Malware Analysis, Threat Intelligence, Supply Chain Security
* **Author:** Security Research Blog

---

## Executive Summary

Supply chain attacks targeting package registries like `npm`, `PyPI`, and `crates.io` have become a standard delivery vector for modern threat actors. By leveraging typosquatting or dependency confusion, attackers trick developers or automated CI/CD systems into executing malicious code upon package installation.

This blog post provides a comprehensive technical teardown of an obfuscated JavaScript InfoStealer sample (`malware.js`). Our analysis reveals a multi-stage payload designed to steal browser credentials, target cryptocurrency wallets, dump system keychains, and recursively harvest sensitive files across the victim's host filesystem before uploading them to a remote Command and Control (C2) server.

---

## 1. Static Analysis & Obfuscation Breakdown

The source file is heavily obfuscated using the popular **`javascript-obfuscator`** (obfuscator.io) framework. The file size stands at approximately 430 KB, indicating a substantial payload hidden behind the boilerplate code.

The obfuscation employs three primary defensive structures:

### A. The Shuffled String Array
At the header of the script, a single parameterless function returns a massive array of base64-encoded strings. Immediately below this definition is an Immediately Invoked Function Expression (IIFE) that shifts the array:

```javascript
(function (J, k) {
  const g = J();
  while (true) {
    try {
      const O = parseInt(b(10888, 0x493f)) / 1 + ...;
      if (O === k) { break; } else { g.push(g.shift()); }
    } catch (H) { g.push(g.shift()); }
  }
})(c, 316705);
```

This IIFE rotates the array until a specific checksum value matching `316705` is hit. This prevents static extraction of string indexes, as the array must be dynamically rotated first.

### B. Two-Tiered String Decryption
The script defines two internal helper functions to resolve string references:
1. **Base64 Decoder (`b`)**: Decodes simple base64-encoded strings from the array.
2. **RC4 Stream Cipher Decoder (`N`)**: Decodes base64 strings and decrypts them using an RC4 key passed as the second argument (e.g., `N(20687, "b(ax")`).

### C. Self-Defending Guardrails (Anti-Beautification)
To hinder analysis, the obfuscator uses verification mechanisms to check if the code has been reformatted or if debugging tools are active:
* **Function.prototype.toString Checking**: A regular expression (`\w+ *\(\) *{\w+ *['|"].+['|"];? *}`) runs against the string representation of core decryption functions. If spacing or newlines are modified during prettification, the check fails, causing the script to lock up.
* **ReDoS Regular Expressions**: RegEx checks designed to trigger a Regular Expression Denial of Service (ReDoS) are executed during load, hanging the JS runtime if debuggers or code beautifiers have altered the structural layout.

---

## 2. Dynamic Interception & Payload Extraction

Rather than dynamically stepping through the complex obfuscation wrappers, we can exploit a key architectural design choice made by the malware author: **nested string execution**.

The core logic of the malware is stored as large plaintext template strings (`k`, `G`, and `g`) which are dynamically constructed and then executed by spawning a detached Node.js process:
`Utils.sp_s(payloadScript, lockFile, scriptName, logger)`.

By writing a custom runner snippet in Chrome DevTools (**Offline Mode**) or a Node.js sandbox, we can mock the `Utils` configuration to intercept these scripts.

### The Interception Hook
```javascript
// Mock global logging and process spawning to prevent actual malware execution
const Utils = {
  sp_s: function(scriptCode, lockFile, scriptName, logger) {
    console.log(`%c[INTERCEPTED PAYLOAD] Name: ${scriptName}`, 'color: #ff9900; font-weight: bold; font-size: 14px;');
    console.log(scriptCode); // Safe execution stop: prints code to stdout/console
  },
  set_l: function(param) { return ""; }
};

const f_s_l = async (msg, level, data) => console.log(`[MOCK LOG] [${level}] ${msg}`);
```

Running the boilerplate with this mock configuration successfully extracts three distinct payload stages.

---

## 3. Deep Dive: Payload Analysis

Once deobfuscated, we map out the complete execution flow of the three payload modules.

### Stage 1: System Profiler & Credential Stealer (`k`)
This payload targets local application data directories. It is cross-platform, handling Windows, macOS, and Linux (including WSL detection).

#### Master Key Recovery
To decrypt browser SQLite credential databases, Stage 1 attempts to recover browser master keys:
* **Windows**: Parses the `Local State` file. It writes a temporary PowerShell script to retrieve the master key using DPAPI:
  `[System.Security.Cryptography.ProtectedData]::Unprotect($encrypted, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)`
* **macOS**: Queries the System Keychain for browser credentials using:
  `security find-generic-password -w -s "Chrome Safe Storage"`
  It then derives the cryptographic key using PBKDF2 with salt `"saltysalt"` and 1003 iterations.
* **Linux**: Queries the local Gnome Keyring or KWallet via `secret-tool lookup` or the `secretstorage` Python module.

#### Target Matrix
The stealer targets the following browsers:
* Google Chrome, Brave, AVG Browser, Microsoft Edge, Opera, Opera GX, Vivaldi, Kiwi Browser, Yandex Browser, Iridium, Comodo Dragon, SRWare Iron, and Chromium.

It copies `Login Data` databases to the temp folder (to bypass file locking), runs `sql.js` to query the credentials, decrypts them, and packages the data into `s.txt`.

#### Crypto Wallets
The script targets browser wallet extensions (MetaMask, Phantom, Coinbase Wallet, Trust Wallet, Rabby, etc.) and parses Brave's native LevelDB wallet storage paths.

---

### Stage 2: Recursive File Crawler (`G`)
Stage 2 crawls the local filesystem looking for sensitive files to exfiltrate.

* **Drive Mapping (Windows)**: Uses PowerShell Cmdlets to dynamically list active logical drives:
  `Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }`
* **Target Keywords**: Scans filenames and extensions against a high-interest list:
  * `.env`, `private_key`, `seed`, `mnemonic`, `wallet`, `credentials`, `bank`, `financ`, `.pem`, `id_rsa`, `.sqlite`, `.pdf`, `.docx`, `.xlsx`.
* **Exclusion List**: To maintain stealth, it skips system and developer folders like `node_modules`, `.git`, `AppData`, `Program Files`, `VMware`, and large media files.
* **Evasion**: Implements a custom adaptive sleep delay between file reads to keep CPU usage low and avoid detection by basic EDR systems.

---

### Stage 3: Websocket Listener (`g`)
The final script maintains interactive access to the infected host:
* Integrates `socket.io-client` to establish a persistent connection back to the C2 server.
* Constantly sends heartbeat logs (`f_s_l`) using a validation signature.
* Listens for remote commands to execute arbitrary payloads or trigger another run of the file crawler.

---

## 4. Indicators of Compromise (IOCs)

Our teardown recovered hardcoded network endpoints and validation secrets:

### A. Network Indicators (C2)
* **Websocket Command Server:** `ws://216.126.225.243:8087/` (API endpoint: `/api/notify`)
* **Logging Collector:** `http://216.126.225.243:8087/api/log`
* **Files Exfiltration Server:** `http://216.126.225.243:8086/upload`
* **Credentials Collector:** `http://216.126.225.243:8085/upload`

### B. Host & Cryptographic Signatures
* **Validation Secret**: `SuperStr0ngSecret@)@^` (Used to sign HTTP requests with HMAC-SHA256: `payload_data + "|" + timestamp`).
* **Campaign Key / Actor ID**: `504`
* **Target Type Code**: `5`

---

## 5. Prevention & Mitigation

To defend development environments against supply chain payloads like `malware.js`:

1. **Verify npm Dependencies**: Use tools like `npm audit` or `socket.dev` to verify the security posture of newly added packages.
2. **Lockfiles & Integrity Checks**: Always commit `package-lock.json` or `yarn.lock`. Force integrity checks during build cycles (`npm ci --ignore-scripts`).
3. **Restrict Hook Scripts**: Disable automatic lifecycle script execution during package installations:
   `npm config set ignore-scripts true`
4. **Outbound Firewall Restrictions**: Block non-standard outbound connections from dev environments. Standard development nodes rarely need direct socket connections to external, raw IP addresses (e.g., `216.126.225.243`).
