import { useEffect, useState } from "react";
import { io } from "socket.io-client";
import { Card, CardContent } from "@/components/ui/card";
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from "@/components/ui/table";
import { AlertCircle } from "lucide-react";

const socket = io("http://localhost:5000");

export default function IDSAlerts() {
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    socket.on("intrusion_alert", (alert) => {
      setAlerts((prevAlerts) => [alert, ...prevAlerts]);
    });
    return () => {
      socket.off("intrusion_alert");
    };
  }, []);

  return (
    <div className="p-6 space-y-4">
      <h1 className="text-xl font-bold">📡 IDS Real-time Alerts</h1>
      <Card>
        <CardContent className="p-4">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Timestamp</TableHead>
                <TableHead>Alert</TableHead>
                <TableHead>PCAP File</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {alerts.map((alert, index) => (
                <TableRow key={index}>
                  <TableCell>{new Date(alert.timestamp * 1000).toLocaleString()}</TableCell>
                  <TableCell className="text-red-600 flex items-center gap-2">
                    <AlertCircle className="text-red-600" /> {alert.message}
                  </TableCell>
                  <TableCell>
                    <a
                      href={`file://${alert.file_path}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-500 underline"
                    >
                      Open PCAP
                    </a>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
