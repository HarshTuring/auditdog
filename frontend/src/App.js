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
    Container
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
                            <ListItem>
                                <ListItemIcon>
                                    <DashboardIcon />
                                </ListItemIcon>
                                <ListItemText primary="Dashboard" />
                            </ListItem>
                            <ListItem>
                                <ListItemIcon>
                                    <LoginIcon />
                                </ListItemIcon>
                                <ListItemText primary="SSH Events" />
                            </ListItem>
                            <ListItem>
                                <ListItemIcon>
                                    <TerminalIcon />
                                </ListItemIcon>
                                <ListItemText primary="Command Executions" />
                            </ListItem>
                            <ListItem>
                                <ListItemIcon>
                                    <AdminIcon />
                                </ListItemIcon>
                                <ListItemText primary="Privilege Escalations" />
                            </ListItem>
                            <ListItem>
                                <ListItemIcon>
                                    <SecurityIcon />
                                </ListItemIcon>
                                <ListItemText primary="Brute Force Attempts" />
                            </ListItem>
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

