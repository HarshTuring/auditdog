import React from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import {
    AppBar,
    Toolbar,
    Typography,
    Box,
    Drawer,
    List,
    ListItem,
    ListItemIcon,
    ListItemText,
    Divider,
    CssBaseline,
    Container,
    ListItemButton
} from '@mui/material';
import {
    Dashboard as DashboardIcon,
    Security as SecurityIcon,
    Terminal as TerminalIcon,
    Login as LoginIcon,
    AdminPanelSettings as AdminIcon
} from '@mui/icons-material';

// Import components
import Dashboard from './components/Dashboard';
import SSHEvents from './components/SSHEvents';
import CommandExecutions from './components/CommandExecutions';
import PrivilegeEscalations from './components/PrivilegeEscalations';
import BruteForceAttempts from './components/BruteForceAttempts';

// Drawer width
const drawerWidth = 240;

function App() {
    return (
        <Router>
            <Box>
                <CssBaseline />
                {/* App Bar */}
                <AppBar>
                    theme.zIndex.drawer + 1

                    <Toolbar>
                        <Typography>
                            AuditDog Monitoring System
                        </Typography>
                    </Toolbar>
                </AppBar>
                {/* Sidebar */}
                <Drawer
                    variant="permanent"
                    sx={{
                        width: drawerWidth,
                        flexShrink: 0,
                        [`& .MuiDrawer-paper`]: {
                            width: drawerWidth,
                            boxSizing: 'border-box'
                        },
                    }}
                >
                    <Toolbar />
                    {/* This creates space for the AppBar */}
                    <Box sx={{ overflow: 'auto' }}>

                        <List>
                            <ListItemButton component={Link} to="/">
                                <ListItemIcon>
                                    <DashboardIcon />
                                </ListItemIcon>
                                <ListItemText primary="Dashboard" />
                            </ListItemButton>
                            <ListItemButton component={Link} to="/ssh-events">
                                <ListItemIcon>
                                    <LoginIcon />
                                </ListItemIcon>
                                <ListItemText primary="SSH Events" />
                            </ListItemButton>
                            <ListItemButton component={Link} to="/command-executions">
                                <ListItemIcon>
                                    <TerminalIcon />
                                </ListItemIcon>
                                <ListItemText primary="Command Executions" />
                            </ListItemButton>
                            <ListItemButton component={Link} to="/privilege-escalations">
                                <ListItemIcon>
                                    <AdminIcon />
                                </ListItemIcon>
                                <ListItemText primary="Privilege Escalations" />
                            </ListItemButton>
                            <ListItemButton component={Link} to="/brute-force">
                                <ListItemIcon>
                                    <SecurityIcon />
                                </ListItemIcon>
                                <ListItemText primary="Brute Force Attempts" />
                            </ListItemButton>
                        </List>
                        <Divider />
                    </Box>
                </Drawer>

                {/* Main content */}
                <Box>
                    <Toolbar />
                    {/* This creates space for the AppBar */}

                    <Container>
                        <Routes>
                            <Route path="/" element={<Dashboard />

                            } />

                            <Route path="/ssh-events" element={<SSHEvents />

                            } />

                            <Route path="/command-executions" element={<CommandExecutions />

                            } />

                            <Route path="/privilege-escalations" element={<PrivilegeEscalations />

                            } />

                            <Route path="/brute-force" element={<BruteForceAttempts />

                            } />

                        </Routes>
                    </Container>
                </Box>
            </Box>
        </Router>
    );
}

export default App;

