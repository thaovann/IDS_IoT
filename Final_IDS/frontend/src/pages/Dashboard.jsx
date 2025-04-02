import React from 'react';
import { Box, Typography, Paper, Grid } from '@mui/material';
import AlertPanel from '../components/AlertPanel';
import NetworkStats from '../components/NetworkStats';
import PacketChart from '../components/PacketChart';

const Dashboard = ({ alerts, stats, socket }) => {
  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom>
        Network Intrusion Detection System
      </Typography>
      
      <Grid container spacing={3}>
        <Grid item xs={12} md={8}>
          <Paper elevation={3} sx={{ p: 2 }}>
            <PacketChart stats={stats} />
          </Paper>
        </Grid>
        
        <Grid item xs={12} md={4}>
          <Paper elevation={3} sx={{ p: 2 }}>
            <NetworkStats stats={stats} />
          </Paper>
        </Grid>
        
        <Grid item xs={12}>
          <Paper elevation={3} sx={{ p: 2 }}>
            <AlertPanel alerts={alerts} />
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Dashboard;