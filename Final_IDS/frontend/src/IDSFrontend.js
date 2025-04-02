import React, { useEffect, useState } from "react";
import { io } from "socket.io-client";

const socket = io("http://127.0.0.1:5000");

const IDSFrontend = () => {
  const [alerts, setAlerts] = useState([]);
  const [predictions, setPredictions] = useState([]);
  const [status, setStatus] = useState({
    packet_count: 0,
    buffer_size: 0,
    last_processed: 0,
  });

  useEffect(() => {
    socket.on("intrusion_alert", (alert) => {
      setAlerts((prevAlerts) => [alert, ...prevAlerts]);
    });

    let isMounted = true;

    const fetchStatus = async () => {
      try {
        const response = await fetch("http://127.0.0.1:5000/status");
        if (!response.ok) throw new Error("Failed to fetch");

        const data = await response.json();
        setStatus(data);
      } catch (error) {
        console.error("Fetch error:", error);
      } finally {
        if (isMounted) setTimeout(fetchStatus, 2000);
      }
    };

    const fetchPredictions = async () => {
      try {
        const response = await fetch("http://127.0.0.1:5000/predictions");
        if (!response.ok) throw new Error("Failed to fetch");

        const data = await response.json();
        setPredictions(data);
      } catch (error) {
        console.error("Fetch error:", error);
      } finally {
        if (isMounted) setTimeout(fetchPredictions, 2000);
      }
    };

    fetchStatus();
    fetchPredictions();

    return () => {
      socket.off("intrusion_alert");
      isMounted = false;
    };
  }, []);

  return (
    <div style={{ padding: "20px", fontFamily: "Arial, sans-serif" }}>
      <h1
        style={{ fontSize: "24px", fontWeight: "bold", marginBottom: "10px" }}
      >
        Real-Time IDS Dashboard
      </h1>

      <div
        style={{
          border: "1px solid #ddd",
          padding: "10px",
          marginBottom: "20px",
          borderRadius: "5px",
        }}
      >
        <h2 style={{ fontSize: "18px", fontWeight: "bold" }}>System Status</h2>
        <p>Packet Count: {status.packet_count}</p>
        <p>Buffer Size: {status.buffer_size}</p>
        <p>Last Processed: {status.last_processed}</p>
      </div>

      <h2 style={{ fontSize: "18px", fontWeight: "bold" }}>Intrusion Alerts</h2>
      <div style={{ maxHeight: "200px", overflowY: "auto" }}>
        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
            marginTop: "10px",
          }}
        >
          <thead>
            <tr style={{ borderBottom: "2px solid #000" }}>
              <th style={{ padding: "8px", textAlign: "left" }}>Timestamp</th>
              <th style={{ padding: "8px", textAlign: "left" }}>Message</th>
              <th style={{ padding: "8px", textAlign: "left" }}>Severity</th>
            </tr>
          </thead>
          <tbody>
            {alerts.slice(0, 5).map((alert, index) => (
              <tr key={index} style={{ borderBottom: "1px solid #ddd" }}>
                <td style={{ padding: "8px" }}>
                  {new Date(alert.timestamp * 1000).toLocaleString()}
                </td>
                <td style={{ padding: "8px" }}>{alert.message}</td>
                <td
                  style={{ padding: "8px", color: "red", fontWeight: "bold" }}
                >
                  {alert.severity}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h2 style={{ fontSize: "18px", fontWeight: "bold", marginTop: "20px" }}>
        Batch Predictions
      </h2>
      <div style={{ maxHeight: "200px", overflowY: "auto" }}>
        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
            marginTop: "10px",
          }}
        >
          <thead>
            <tr style={{ borderBottom: "2px solid #000" }}>
              <th style={{ padding: "8px", textAlign: "left" }}>Batch</th>
              <th style={{ padding: "8px", textAlign: "left" }}>Timestamp</th>
              <th style={{ padding: "8px", textAlign: "left" }}>Predictions</th>
            </tr>
          </thead>
          <tbody>
            {predictions.slice(0, 5).map((pred, index) => (
              <tr key={index} style={{ borderBottom: "1px solid #ddd" }}>
                <td style={{ padding: "8px" }}>{pred.batch}</td>
                <td style={{ padding: "8px" }}>
                  {new Date(pred.timestamp * 1000).toLocaleString()}
                </td>
                <td style={{ padding: "8px" }}>
                  {JSON.stringify(pred.predictions)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default IDSFrontend;
