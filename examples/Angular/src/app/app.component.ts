import { Component, OnInit } from '@angular/core';
import { io } from 'socket.io-client';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css'],
})
export class AppComponent implements OnInit {
  title = 'socket-io-client';

  ngOnInit() {
    // Connect to each port
    // Para utilizar o traffic_analyzer_v2.py com esse exemplo, remova os números 50001 e 50002 do array abaixo:
    this.createSocketConnection(8000);
  }

  createSocketConnection(port: number) {
    const socket = io(`http://localhost:${port}`);

    socket.on('connect', () => {
      console.log(`Connected to localhost:${port}`);
      // You can send data through the socket here
      socket.emit('message', `Hello from port ${port}`);
    });

    //Para a V2 basta ouvir o evento "data"
    socket.on('data', (data: any) => {
      console.log(JSON.stringify(data, null, 2));
      // Handle received data
    });

    //Para a V1 existem esses 3 métodos comentados abaixo
    // socket.on('trafficData', (data: any) => {
    //   console.log(JSON.stringify(data, null, 2));
    //   // Handle received data
    // });

    // socket.on('protocolTraffic', (data: any) => {
    //   console.log(JSON.stringify(data, null, 2));
    //   // Handle received data
    // });

    // socket.on('hostnameTraffic', (data: any) => {
    //   console.log(JSON.stringify(data, null, 2));
    //   // Handle received data
    // });

    socket.on('disconnect', () => {
      console.log(`Connection closed on localhost:${port}`);
    });

    socket.on('error', (err: any) => {
      console.error(`Socket error on localhost:${port}:`, err);
    });
  }
}
