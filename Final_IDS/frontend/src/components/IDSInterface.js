import React, { useState, useEffect } from "react";
import { io } from "socket.io-client";
import axios from "axios";
import { ShieldAlert, PlayCircle } from "lucide-react";

const socket = io("http://127.0.0.1:5000");

// ✅ Tạo component Card thủ công bằng Tailwind
const Card = ({ children }) => (
  <div className="bg-yellow-200 border-l-4 border-red-500 p-4 rounded-lg shadow-md">
    {children}
  </div>
);

export default function IDSInterface() {
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    socket.on("intrusion_alert", (data) => {
      setAlerts((prevAlerts) => [data, ...prevAlerts.slice(0, 9)]);
    });

    return () => socket.off("intrusion_alert");
  }, []);

  const startSniffing = async () => {
    await axios.get("http://127.0.0.1:5000/api/start_sniffing");
    alert("Sniffer đã khởi động!");
  };

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-3xl font-bold">Hệ thống IDS</h1>
      <button
        onClick={startSniffing}
        className="bg-red-500 text-white px-4 py-2 rounded flex items-center space-x-2"
      >
        <PlayCircle /> <span>Bắt Đầu Bắt Gói Tin</span>
      </button>
      <h2 className="text-2xl font-semibold">Cảnh báo gần đây</h2>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {alerts.map((alert, index) => (
          <Card key={index}>
            <ShieldAlert />
            <p className="text-lg font-medium">{alert.message}</p>
            <p className="text-sm">Thời gian: {alert.timestamp}</p>
          </Card>
        ))}
      </div>
    </div>
  );
}
