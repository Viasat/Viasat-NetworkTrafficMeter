const express = require("express");
const app = express();
const http = require("http").createServer(app);
const io = require("socket.io")(http, {
  cors: {
    origin: "*",
  },
});
const net = require("net");

const HOST = "127.0.0.1";
const PORT_NETWORK_TRAFFIC = 50000;
const PORT_PROTOCOL_TRAFFIC = 50001;
const PORT_HOSTNAME_TRAFFIC = 50002;

// Connect to the server socket
const network_client = new net.Socket();
network_client.connect(PORT_NETWORK_TRAFFIC, HOST, () => {
  console.log("Conectado ao provedor de tráfego por aplicativo.");
});

const protocol_client = new net.Socket();
protocol_client.connect(PORT_PROTOCOL_TRAFFIC, HOST, () => {
  console.log("Conectado ao provedor de tráfego por protocolo de rede.");
});

const hostname_client = new net.Socket();
hostname_client.connect(PORT_HOSTNAME_TRAFFIC, HOST, () => {
  console.log("Conectado ao provedor de tráfego por hosts.");
});

io.on("connection", (socket) => {
  network_client.on("data", (data) => {
    socket.emit("networkTraffic", JSON.parse(data));
  });

  protocol_client.on("data", (data) => {
    socket.emit("protocolTraffic", JSON.parse(data));
  });

  hostname_client.on("data", (data) => {
    socket.emit("hostnameTraffic", JSON.parse(data));
  });
});
// Start the server
http.listen(8000, () => {
  console.log("Server iniciou na porta 8000");
});
