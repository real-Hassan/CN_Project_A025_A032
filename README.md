CENTIPEDE // Advanced Packet Sniffer 🐛

**Centipede** is a custom-built, high-performance packet sniffer and network analysis tool designed for Windows. It features a low-level C++ backend for live network capture, a Node.js middleware bridge, and a real-time, cyberpunk-themed web dashboard for Deep Packet Inspection (DPI).

---

## 📖 Table of Contents
- [How It Works](#-how-it-works)
- [System Requirements](#-system-requirements)
- [Usage Instructions](#-usage-instructions)
- [Features](#-features)
- [Authors](#-authors)

---

## 🧠 How It Works

Centipede operates on a decoupled, three-tier architecture, allowing high-performance packet processing without blocking the user interface:

1. **The C++ Backend (`sniffer.exe`):**
   - Utilizes Windows Sockets (`winsock2.h`) and Microsoft-specific extensions (`mstcpip.h` via `SIO_RCVALL`) to bind to a network interface and enable **promiscuous mode**. This allows the program to intercept all incoming and outgoing IP packets, regardless of their destination.
   - It performs deep packet inspection by manually parsing Layer 3 (IPv4) and Layer 4 (TCP, UDP, ICMP) headers.
   - Calculates and verifies checksums for IP, TCP, and UDP to ensure data integrity.
   - Formats the extracted data and payload into a structured JSON string and emits it to the standard output (`stdout`).

2. **The Node.js Middleware (`server.js`):**
   - Acts as a real-time bridge. It spawns the C++ `sniffer.exe` as a child process and continuously reads its `stdout`.
   - It filters the terminal text to isolate the valid JSON packet data.
   - Hosts a local WebSocket server (typically on `ws://localhost:8080`) and broadcasts the live JSON packet data to any connected frontend clients.

3. **The Frontend Dashboard (`interface.html`):**
   - A Single Page Application (SPA) built with HTML5, CSS3, and vanilla JavaScript.
   - Connects to the Node.js WebSocket server to receive packet data with zero perceived latency.
   - Manages a high-performance buffer (capped at 5,000 packets to prevent browser freezing) and renders the data in an interactive table.
   - Provides real-time filtering, hex/ASCII payload dumps, and detailed packet field decoding upon clicking a packet row.

---

## ⚙️ System Requirements

To compile and run this project, your system must meet the following requirements:

* **Operating System:** Windows 10 or Windows 11 (Strictly required due to the reliance on the Windows Sockets API `ws2_32.lib`).
* **C++ Compiler:** [MinGW-w64](https://www.mingw-w64.org/) (Minimalist GNU for Windows). You must have `g++` installed and added to your system's `PATH` variable to compile the C++ source code.
* **JavaScript Runtime:** [Node.js](https://nodejs.org/) (Version 14.x or higher is recommended) installed and added to your `PATH`.
* **Privileges:** **Administrator privileges are absolutely mandatory.** Windows will block raw socket creation and promiscuous mode if the program is not run with elevated rights.

---


### Step 3: Compile the C++ Backend using MinGW
Ensure MinGW is installed and configured in your environment variables. Open a terminal in the project directory and compile `sniffer.cpp`:
```bash
g++ sniffer.cpp -o sniffer.exe -lws2_32
```
*Note: The `-lws2_32` flag is crucial as it links the Windows Sockets library.*

---

## 🎮 Usage Instructions

> **⚠️ CRITICAL:** You must run your terminal/command prompts as **Administrator** for the application to work. Without Administrator rights, the C++ sniffer will fail to bind the raw socket.

**1. Start the Node.js Bridge Server:**
Open an Administrator terminal, navigate to the project directory, and run:
```bash
node server.js
```
*(You should see a message indicating the Bridge Server is running on `ws://localhost:8080`)*

**2. Start the Packet Sniffer:**
Leave the first terminal running. Open a **second Administrator terminal**, navigate to the project directory, and run the compiled executable:
```bash
.\\sniffer.exe
```
*(The console will display the local IP it is sniffing on and begin printing packet summaries)*

**3. Launch the UI:**
Simply double-click the `interface.html` file to open it in your preferred modern web browser (Chrome, Edge, Firefox).
- The top bar should indicate the status as **CONNECTED** (with a pulsing green dot).
- Packets will immediately begin populating the table.

---

## 🌟 Features Highlight

* **Raw Socket Capture:** Deep integration with Windows network interfaces.
* **Manual Checksum Verification:** Recalculates and flags invalid IP, TCP, and UDP checksums.
* **Hex & ASCII Payload Dumps:** Inspect raw data byte-by-byte for security analysis.
* **Wireshark-Style Filtering:** Use strict syntax (e.g., `tcp.port == 443`, `ip.addr == 192.168.1.1`) or broad string searches to isolate specific traffic.
* **High-Performance UI:** Safely handles high-throughput network traffic without locking up the browser.

---

## 👨‍💻 Authors

* **Muhammad Bilal Khan** (BCSF24A032)
* **Muhammad Hassan Farooq** (BCSF24A025)

*Developed for the Computer Networks academic project.*
"""

output_path = '/mnt/data/README.md'
with open(output_path, 'w', encoding='utf-8') as f:
    f.write(readme_content)

print(f"[file-tag: {output_path}]")

```
Your Markdown file is ready
[file-tag: code-generated-file-0-1777917182635085834]

I have generated a highly detailed `README.md` tailored specifically for GitHub. It includes clear explanations of the decoupled architecture (how the C++, Node.js, and HTML files interact), strictly lists the system requirements (including MinGW and the necessity of Windows/Administrator privileges), and provides a step-by-step setup guide with all the correct terminal commands. 

Let me know if you need any adjustments to the structure or instructions!