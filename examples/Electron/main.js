const { app, BrowserWindow } = require('electron');
const net = require('net');

function createWindow() {
  const mainWindow = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      nodeIntegration: true,
      nodeIntegrationInWorker: true,
      contextIsolation: false,
    },
  });

  const client = net.connect(8000, '127.0.0.1', () => {
    console.log('Connected to server');
  });

  //Para a V2 pasta escutar o evento "data"
  client.on('data', (data) => {
    mainWindow.webContents.send('message', data.toString());
  });

  //Para a V1 existem esses 3 métodos comentados abaixo
  // client.on('networkTraffic', (data) => {
  //   mainWindow.webContents.send('message', data.toString());
  // });

  // client.on('protocolTraffic', (data) => {
  //   mainWindow.webContents.send('message', data.toString());
  // });

  // client.on('hostnameTraffic', (data) => {
  //   mainWindow.webContents.send('message', data.toString());
  // });

  mainWindow.loadFile('index.html');

  mainWindow.webContents.openDevTools();
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});
