import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  Box,
  Button,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  CircularProgress,
  Alert,
} from "@mui/material";
import {
  getAlertDetail,
  getDownloadCsvUrl,
  getDownloadPcapUrl,
  getCsvData,
} from "../services/api";
import { CSVLink } from "react-csv";
import { formatVNDateTime } from "../utils/dateTime";
const AlertDetailPage = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [rows, setRows] = useState([]);
  const [columns, setColumns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const csvHeaders = columns.map((col) => ({ label: col, key: col }));

  useEffect(() => {
    const fetchAlertData = async () => {
      try {
        const alert = await getAlertDetail(id);
        if (!alert) throw new Error("No alert data received");
  
        const csvResult = await getCsvData(id);
  
        console.log("📦 Full CSV result:", csvResult);
        console.log("🧪 Type:", typeof csvResult);
        console.log("📑 Keys:", Object.keys(csvResult));
  
        setColumns(csvResult?.columns ?? []);
        setRows(csvResult?.rows ?? []);
      } catch (err) {
        console.error("Failed to load alert data:", err);
        setError("Không thể tải dữ liệu cảnh báo.");
      } finally {
        setLoading(false);
      }
    };
  
    fetchAlertData();
  }, [id]);
  const formatTimestamp = (row) => {
    if (row.Timestamp) {
      return formatVNDateTime(row.Timestamp);
    }
    return row.Timestamp || "";
  };

  return (
    <Box>
      <Box sx={{ mb: 2, display: "flex", flexWrap: "wrap", gap: 2 }}>
        <Button variant="outlined" onClick={() => navigate("/dashboard")}>
          🔙 Trở về Dashboard
        </Button>

        <Button
          variant="contained"
          color="primary"
          href={getDownloadCsvUrl(id)}
          target="_blank"
        >
          📄 Tải CSV
        </Button>
        <Button
          variant="contained"
          color="secondary"
          href={getDownloadPcapUrl(id)}
          target="_blank"
        >
          🗂️ Tải PCAP
        </Button>
      </Box>

      {loading ? (
        <CircularProgress />
      ) : error ? (
        <Alert severity="error">{error}</Alert>
      ) : rows.length === 0 ? (
        <Alert severity="info">Không có dữ liệu CSV để hiển thị.</Alert>
      ) : (
        <Paper sx={{ maxHeight: 700, overflow: "auto" }}>
          <TableContainer>
            <Table stickyHeader size="small">
              <TableHead>
                <TableRow>
                  {columns.map((col) => (
                    <TableCell key={col}>{col}</TableCell>
                  ))}
                </TableRow>
              </TableHead>
              <TableBody>
                {rows.map((row, idx) => (
                  <TableRow
                    key={idx}
                    sx={
                      row.Label !== "No Label"
                        ? { backgroundColor: "#fff3e0" }
                        : {}
                    }
                  >
                    {columns.map((col) => (
                      <TableCell key={col}>
                        {row[col] !== undefined ? String(row[col]) : ""}
                      </TableCell>
                    ))}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      )}
    </Box>
  );
};

export default AlertDetailPage;
