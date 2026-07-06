---
title: "Unpacking malware2.exe: How a Typosquatted npm Package Delivers a Packed V8 Bytecode Stealer"
---

# Unpacking malware2.exe: How a Typosquatted npm Package Delivers a Packed V8 Bytecode Stealer

* **Category:** Reverse Engineering, Malware Analysis, Threat Intelligence
* **Target Sample:** malware2.exe (WDYMStealer)
* **SHA-256:** `6b7c1278dcf4374d7c59c0162adcd92d938c0f1e53e2dc5a3628e82a91b9bf42`

---

## Introduction

In this blog post, we are going to look closely at a malware sample called `malware2.exe`. This file comes from a malicious supply chain attack targeting Node.js developers via an npm package named `wdym`. 

At first glance, `malware2.exe` looks huge—about **54 Megabytes**! Why is a simple stealer script so massive? 

The answer lies in how it was built. It was packaged using **`vercel/pkg`**, a tool that compiles Node.js applications into single self-contained executables. This means the 54 MB file contains the entire Node.js runtime, the V8 engine, the attacker's JavaScript code, and even a secondary binary payload tucked inside a virtual filesystem. 

Let's walk through exactly how to unpack this executable step-by-step and inspect what is hidden inside.

---

## 1. How Vercel `pkg` Packs Files

Before we start dissecting the malware, we need to understand how the `pkg` packaging tool works. 

When you run `pkg`, it creates an executable structure that looks like this:
1. **The Node.js base binary:** A standard, precompiled Node.js executable (about 37 MB).
2. **The Virtual Filesystem (VFS) Payload:** A block of data appended directly after the Node.js executable. It contains all the bundled scripts, packages, and assets.
3. **The Metadata Footer:** A JSON map appended at the very end of the file. It lists the files, their virtual paths (usually starting with `C:\snapshot\`), their offset locations, and their sizes.

At the end of the Node.js base binary, the packaging code defines a marker variable called `PAYLOAD_POSITION` which tells the runtime exactly where the virtual filesystem starts.

---

## 2. Locating the Payload Offsets

By inspecting the final bytes of `malware2.exe`, we can locate the virtual directory manifest. The footer ends with a JSON map that maps files to their positions inside the payload:

```json
{
  "C:\\snapshot\\build_1782334482923\\index.js": {
    "0": [0, 89888],
    "3": [89888, 121]
  },
  "C:\\snapshot\\build_1782334482923\\package.json": {
    "1": [90009, 190],
    "3": [90199, 119]
  },
  "C:\\snapshot\\build_1782334482923\\assets.exe": {
    "1": [90318, 16368833],
    "3": [16459151, 124]
  }
}
```

### Deciphering the JSON Map:
* **Key `"0"`** represents JavaScript source code.
* **Key `"1"`** represents binary assets/buffers.
* **Key `"3"`** represents compilation metadata/bytecode headers.
* **Offsets and Sizes:** The array values like `[0, 89888]` indicate `[PayloadOffset, FileSize]`.

From this metadata, we can see that the payload bundles three files:
1. **`index.js`**: The main JavaScript execution file (size: `89,888` bytes).
2. **`package.json`**: The npm package configuration (size: `190` bytes).
3. **`assets.exe`**: A massive embedded binary file (size: `16,368,833` bytes, or ~16.3 MB!).

---

## 3. Finding the Start Position

To extract these files, we need to know the absolute byte offset where the VFS payload block begins. We can find this by scanning the executable for the internal variable `PAYLOAD_POSITION`. 

In our sample, searching for the string `PAYLOAD_POSITION` yields:
```javascript
var PAYLOAD_POSITION = '37574656              ' | 0;
```
This tells us the payload block starts exactly at byte **`37,574,656`**. 

Using this, we can calculate the absolute offsets for each file on the disk:
* **`index.js` absolute position:** `37,574,656 + 0` (starts at 37,574,656, ends at 37,664,544).
* **`package.json` absolute position:** `37,574,656 + 90,009` (starts at 37,664,665, ends at 37,664,855).
* **`assets.exe` absolute position:** `37,574,656 + 90,318` (starts at 37,664,974, ends at 54,033,807).

---

## 4. Writing an Unpacker Script

Since we cannot run the malware directly, we can write a simple, safe Python script to slice these files out of the binary:

```python
import os

exe_path = "malware2.exe"
out_dir = "unpacked_malware2"

if not os.path.exists(out_dir):
    os.makedirs(out_dir)

# Value parsed from var PAYLOAD_POSITION
payload_position = 37574656

# File map derived from the JSON trailer
targets = {
    "index.js": (0, 89888),
    "package.json": (90009, 190),
    "assets.exe": (90318, 16368833)
}

print("[*] Unpacking malware2.exe...")
with open(exe_path, "rb") as f:
    for filename, (offset, size) in targets.items():
        # Jump to absolute offset
        f.seek(payload_position + offset)
        file_data = f.read(size)
        
        # Save output file
        out_path = os.path.join(out_dir, filename)
        with open(out_path, "wb") as out_f:
            out_f.write(file_data)
        print(f"[+] Extracted: {filename} ({len(file_data)} bytes)")
```

---

## 5. Analyzing the Unpacked Files

Once extracted, we analyze each file to understand the malware's components.

### File A: `package.json`
Reading this file shows the npm configuration:
```json
{
  "name": "wdym",
  "version": "1.0.0",
  "main": "index.js",
  "bin": "index.js",
  "pkg": {
    "assets": ["assets.exe"],
    "targets": ["node18-win-x64"]
  }
}
```
This confirms the package name is `wdym` and lists `assets.exe` as a bundled asset.

### File B: `index.js` (The V8 Bytecode Loader)
When we open `index.js`, we don't see plain JavaScript. Instead, it starts with the hex sequence `62 05 de c0`. 

This signature represents **V8 Bytecode**. Rather than distributing raw JS code, `pkg` compiles the script directly into V8 engine bytecode. While this prevents simple text-based decompilation, the file still contains plain ASCII strings embedded inside it. 

Dumping the strings from the bytecode reveals the core behavior:
1. **Anti-VM and Anti-Analysis:**
   The script contains a long list of network MAC addresses associated with Virtual Machines (e.g. VMware, VirtualBox, Hyper-V). It checks the infected system's network adapter MAC addresses and halts execution if a virtualized environment is detected.
2. **Discord Token Stealing:**
   It contains path strings for various Discord clients (`Discord Canary`, `Discord PTB`, `Lightdiscord`) and lists functions like `collectTokens` and `decryptToken` to grab active Discord auth keys.
3. **Payload Extraction:**
   Because Windows cannot run a binary (`assets.exe`) directly from inside another program's memory VFS container, the code in `index.js` extracts `assets.exe` out of `/snapshot/` to the victim's temporary directory (`%TEMP%`) and executes it using Node's `child_process.execSync` or `spawn`.

### File C: `assets.exe` (The PyInstaller Payload)
The extracted `assets.exe` starts with a standard PE header (`MZ`). Threat intelligence checks reveal that this is a **PyInstaller-compiled stealer executable** belonging to the **WDYMStealer** family. 

Once executed by the `index.js` loader, this binary performs the heavy lifting: gathering credentials, capturing files, and uploading them.

---

## 6. Command and Control (C2) Indicators of Compromise (IOCs)

Our string extraction recovered the following C2 Discord Webhooks and endpoints from the V8 bytecode:

* **IP Lookup Check**: `https://api.ipify.org`
* **Discord C2 Webhook 1**: `https://discord.com/api/webhooks/1519426845869609110/p1_ZkCrFjg4KoZH5ET7NwogBUT5oL-SnTd-X8us392hADg4VAfgFWW0IYK-5I2Nr7DWV`
* **Discord C2 Webhook 2**: `https://discord.com/api/webhooks/1519445480189202592/Xi8kWUHY3ikAGOOhYiWv4zC1p6y3CV6dnWKRsC_OI_hivlrAc592a8yBuI9Re-35Kvql`
* **Image Staging Site**: `https://ibb.co/93mnpzVJ` (ImgBB hosting, likely for uploading screenshots).

---

## Conclusion

`malware2.exe` represents a classic two-stage loader architecture hidden inside a bundled runtime container:
1. The **Outer Wrapper** (Node.js runtime + `pkg` VFS) executes V8 bytecode.
2. The **Bytecode script** performs anti-VM virtualization checks, grabs basic Discord info, and drops the secondary payload to disk.
3. The **Inner Payload** (`assets.exe`, compiled with PyInstaller) executes the main data-stealing mechanisms and uploads the results to C2 channels.

By using simple file carving techniques, we bypassed the packaging layer and recovered the core components, hashes, and network indicators without ever putting the analysis machine at risk.

