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
const PORT_TRAFFIC = 50000;

// Connect to the server socket
const network_client = new net.Socket();
network_client.connect(PORT_TRAFFIC, HOST, () => {
  console.log("Conectado ao provedor de tráfego.");
});

io.on("connection", (socket) => {
  network_client.on("data", (data) => {
    socket.emit("data", JSON.parse(data));
  });
});
// Start the server
http.listen(8000, () => {
  console.log("Server iniciou na porta 8000");
});
