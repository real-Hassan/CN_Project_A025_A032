const { spawn } = require('child_process');
const WebSocket = require('ws');
const readline = require('readline');

// 1. WebSocket bridge for the frontend
const wss = new WebSocket.Server({ port: 8080 });
console.log("📡 Bridge Server running on ws://localhost:8080");

// 2. Spawn the C++ sniffer
const sniffer = spawn('sniffer.exe');

// 3. Read C++ stdout line by line
const rl = readline.createInterface({ input: sniffer.stdout, terminal: false });

rl.on('line', (line) => {
    const t = line.trim();

    // The C++ sniffer emits one "[JSON] {...}" line per packet.
    // Everything else is the human-readable terminal dump — ignore it here.
    if (!t.startsWith('[JSON]')) return;

    try {
        const json = t.slice(6).trim();   // strip the "[JSON] " prefix
        JSON.parse(json);                 // validate before forwarding
        broadcast(json);
    } catch (err) {
        console.error("JSON parse error:", err.message, "→", t);
    }
});

// 4. Broadcast to all connected WebSocket clients
function broadcast(message) {
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(message);
        }
    });
}

sniffer.stderr.on('data', (data) => console.error(`[C++ Error] ${data.toString().trim()}`));
sniffer.on('close', (code) => console.log(`Sniffer exited with code ${code}`));