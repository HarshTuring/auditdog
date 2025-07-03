import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, useNavigate } from 'react-router-dom';
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
    IconButton,
    useTheme,
    useMediaQuery
} from '@mui/material';
import {
    Dashboard as DashboardIcon,
    Security as SecurityIcon,
    Terminal as TerminalIcon,
    Login as LoginIcon,
    AdminPanelSettings as AdminIcon,
    Menu as MenuIcon,
    ChevronLeft as ChevronLeftIcon,
    BarChart as BarChartIcon
} from '@mui/icons-material';

// Import components
import Dashboard from './components/Dashboard';
import SSHEvents from './components/SSHEvents';
import CommandExecutions from './components/CommandExecutions';
import PrivilegeEscalations from './components/PrivilegeEscalations';
import BruteForceAttempts from './components/BruteForceAttempts';
import LogAnalytics from './components/LogAnalytics';

// Drawer width
const drawerWidth = 240;

const Navigation = ({ drawerOpen, setDrawerOpen, drawerWidth }) => {
    const navigate = useNavigate();
    const theme = useTheme();
    const isMobile = useMediaQuery(theme.breakpoints.down('sm'));
    const menuItems = [
        { text: 'Log Analytics', icon: <BarChartIcon />, path: '/log-analytics' },
        { text: 'Dashboard', icon: <DashboardIcon />, path: '/' },
        { text: 'SSH Events', icon: <LoginIcon />, path: '/ssh-events' },
        { text: 'Command Executions', icon: <TerminalIcon />, path: '/command-executions' },
        { text: 'Privilege Escalations', icon: <AdminIcon />, path: '/privilege-escalations' },
        { text: 'Brute Force Attempts', icon: <SecurityIcon />, path: '/brute-force' },
    ];
    const handleNavigate = (path) => {
        navigate(path);
        if (isMobile) {
            setDrawerOpen(false);
        }
    };
    return (
        <Drawer
            variant={isMobile ? 'temporary' : 'permanent'}
            open={drawerOpen}
            onClose={() => setDrawerOpen(false)}
            sx={{
                width: drawerWidth,
                flexShrink: 0,
                '& .MuiDrawer-paper': {
                    width: drawerWidth,
                    boxSizing: 'border-box',
                    transition: theme.transitions.create(['width', 'margin'], {
                        easing: theme.transitions.easing.sharp,
                        duration: theme.transitions.duration.enteringScreen,
                    }),
                },
                ...(isMobile ? {} : {
                    width: drawerOpen ? drawerWidth : theme.spacing(7),
                    '& .MuiDrawer-paper': {
                        width: drawerOpen ? drawerWidth : theme.spacing(7),
                        overflowX: 'hidden',
                    },
                })
            }}
        >
            <Toolbar sx={{ display: 'flex', alignItems: 'center', justifyContent: drawerOpen ? 'space-between' : 'center', px: [1] }}>
                <IconButton onClick={() => setDrawerOpen(false)}>
                    <ChevronLeftIcon />
                </IconButton>
            </Toolbar>
            <Divider />
            <Box sx={{ flexGrow: 1 }}>
                <List>
                    {menuItems.map((item) => (
                        <ListItem
                            key={item.text}
                            onClick={() => handleNavigate(item.path)}
                            sx={{
                                cursor: 'pointer',
                                minHeight: 48,
                                px: 2.5,
                                justifyContent: drawerOpen ? 'initial' : 'center',
                            }}
                        >
                            <ListItemIcon>
                                {item.icon}
                            </ListItemIcon>
                            <ListItemText primary={item.text} sx={{ opacity: drawerOpen ? 1 : 0 }} />
                        </ListItem>
                    ))}
                </List>
            </Box>
        </Drawer>
    );
};

function AppContent() {
    const [drawerOpen, setDrawerOpen] = useState(true);
    const theme = useTheme();
    const isMobile = useMediaQuery(theme.breakpoints.down('sm'));
    React.useEffect(() => {
        if (isMobile) {
            setDrawerOpen(false);
        } else {
            setDrawerOpen(true);
        }
    }, [isMobile]);
    return (
        <Box sx={{ display: 'flex' }}>
            <CssBaseline />
            <AppBar
                position="fixed"
                sx={{
                    zIndex: theme.zIndex.drawer + 1,
                    transition: theme.transitions.create(['width', 'margin'], {
                        easing: theme.transitions.easing.sharp,
                        duration: theme.transitions.duration.leavingScreen,
                    }),
                    ...(drawerOpen && {
                        marginLeft: drawerWidth,
                        width: `calc(100% - ${drawerWidth}px)`,
                        transition: theme.transitions.create(['width', 'margin'], {
                            easing: theme.transitions.easing.sharp,
                            duration: theme.transitions.duration.enteringScreen,
                        }),
                    }),
                }}
            >
                <Toolbar>
                    <IconButton
                        color="inherit"
                        aria-label="open drawer"
                        onClick={() => setDrawerOpen(!drawerOpen)}
                        edge="start"
                        sx={{ mr: 2 }}
                    >
                        <MenuIcon />
                    </IconButton>
                    <Typography variant="h6" noWrap component="div">
                        AuditDog Monitoring System
                    </Typography>
                </Toolbar>
            </AppBar>
            <Navigation drawerOpen={drawerOpen} setDrawerOpen={setDrawerOpen} drawerWidth={drawerWidth} />
            <Box
                component="main"
                sx={{
                    flexGrow: 1,
                    p: 0,
                    transition: theme.transitions.create('margin', {
                        easing: theme.transitions.easing.sharp,
                        duration: theme.transitions.duration.leavingScreen,
                    }),
                    ...(drawerOpen && !isMobile && {
                        transition: theme.transitions.create('margin', {
                            easing: theme.transitions.easing.easeOut,
                            duration: theme.transitions.duration.enteringScreen,
                        }),
                    }),
                }}
            >
                <Toolbar />
                <Container>
                    <Routes>
                        <Route path="/log-analytics" element={<LogAnalytics />} />
                        <Route path="/" element={<Dashboard />} />
                        <Route path="/ssh-events" element={<SSHEvents />} />
                        <Route path="/command-executions" element={<CommandExecutions />} />
                        <Route path="/privilege-escalations" element={<PrivilegeEscalations />} />
                        <Route path="/brute-force" element={<BruteForceAttempts />} />
                    </Routes>
                </Container>
            </Box>
        </Box>
    );
}

function App() {
    return (
        <Router>
            <AppContent />
        </Router>
    );
}

export default App;

