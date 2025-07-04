import React, { useState, useEffect } from 'react';
import {
    Box,
    Grid,
    Paper,
    Typography,
    MenuItem,
    FormControl,
    InputLabel,
    Select,
    CircularProgress,
    Divider
} from '@mui/material';
import {
    LineChart,
    Line,
    BarChart,
    Bar,
    PieChart,
    Pie,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    Legend,
    ResponsiveContainer,
    Cell
} from 'recharts';
import { format, subDays, startOfDay, endOfDay } from 'date-fns';

import { sshEventsApi, commandExecutionsApi, privilegeEscalationsApi, bruteForceApi } from '../api/api';

// Color palette for charts
const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884d8', '#FF5733'];
const SUCCESS_COLOR = '#00C49F';
const FAILURE_COLOR = '#FF5733';
const RISK_COLORS = {
    critical: '#d32f2f',
    high: '#f44336',
    medium: '#ff9800',
    low: '#4caf50',
    minimal: '#2196f3',
};

const TimeRangeSelector = ({ timeRange, setTimeRange }) => {
    return (
        <FormControl>
            <InputLabel>Time Range</InputLabel>
            <Select
                value={timeRange}
                label="Time Range"
                onChange={e => setTimeRange(Number(e.target.value))}
            >
                <MenuItem value={1}>Last 24 hours</MenuItem>
                <MenuItem value={7}>Last 7 days</MenuItem>
                <MenuItem value={30}>Last 30 days</MenuItem>
                <MenuItem value={90}>Last 90 days</MenuItem>
                <MenuItem value={365}>Last 1 year</MenuItem>
                <MenuItem value={730}>Last 2 years</MenuItem>
            </Select>
        </FormControl>
    );
};

// Chart for SSH events - line chart showing logins per hour (total, since backend does not split by success/failure per hour)
const SSHEventsChart = ({ timeRange }) => {
    const [data, setData] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const fetchData = async () => {
            try {
                setLoading(true);
                const startDate = startOfDay(subDays(new Date(), timeRange));
                const params = {};
                if (startDate) {
                    params.start_time = startDate.toISOString();
                }
                if (!params.start_time) {
                    params.lookback_hours = timeRange * 24;
                }
                const stats = await sshEventsApi.getStats(params);
                // events_by_hour: { [hour: 0-23]: count }
                const dataArr = Array.from({ length: 24 }).map((_, hour) => ({
                    hour,
                    logins: stats.events_by_hour && stats.events_by_hour[hour] ? stats.events_by_hour[hour] : 0
                }));
                setData(dataArr);
                setError(null);
            } catch (err) {
                console.error('Error fetching SSH event stats:', err);
                setError(err.message || 'Failed to load SSH event statistics');
            } finally {
                setLoading(false);
            }
        };
        fetchData();
    }, [timeRange]);

    if (loading) return <CircularProgress />;
    if (error) return <Typography color="error">{error}</Typography>;

    return (
        <Box sx={{ width: '100%', height: 320 }}>
            <ResponsiveContainer width="100%" height="100%">
                <LineChart data={data}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="hour" label={{ value: 'Hour of Day', position: 'insideBottomRight', offset: 0 }} />
                    <YAxis />
                    <Tooltip formatter={(value) => [`${value} logins`, 'Logins']} labelFormatter={label => `Hour: ${label}`} />
                    <Legend />
                    <Line type="monotone" dataKey="logins" stroke={SUCCESS_COLOR} name="Logins" />
                </LineChart>
            </ResponsiveContainer>
        </Box>
    );
};

// Chart for Command Executions - bar chart showing command risk distribution
const CommandExecutionsChart = ({ timeRange }) => {
    const [data, setData] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const fetchData = async () => {
            try {
                setLoading(true);
                const startDate = startOfDay(subDays(new Date(), timeRange));
                const params = {};
                if (startDate) {
                    params.start_time = startDate.toISOString();
                }
                if (!params.start_time) {
                    params.lookback_hours = timeRange * 24;
                }
                const stats = await commandExecutionsApi.getStats(params);
                // events_by_risk: { [risk_level]: count }
                const dataArr = Object.entries(stats.events_by_risk || {}).map(([risk, count]) => ({
                    name: risk.charAt(0).toUpperCase() + risk.slice(1),
                    count
                }));
                setData(dataArr);
                setError(null);
            } catch (err) {
                console.error('Error fetching command execution stats:', err);
                setError(err.message || 'Failed to load command execution statistics');
            } finally {
                setLoading(false);
            }
        };
        fetchData();
    }, [timeRange]);

    if (loading) return <CircularProgress />;
    if (error) return <Typography color="error">{error}</Typography>;

    return (
        <Box sx={{ width: '100%', height: 320 }}>
            <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <Tooltip formatter={(value) => [`${value} commands`, 'Count']} />
                    <Legend />
                    <Bar dataKey="count" name="Count">
                        {data.map((entry, index) => (
                            <Cell
                                key={`cell-${index}`}
                                fill={
                                    entry.name === 'Critical' ? RISK_COLORS.critical :
                                    entry.name === 'High' ? RISK_COLORS.high :
                                    entry.name === 'Medium' ? RISK_COLORS.medium :
                                    entry.name === 'Low' ? RISK_COLORS.low :
                                    RISK_COLORS.minimal
                                }
                            />
                        ))}
                    </Bar>
                </BarChart>
            </ResponsiveContainer>
        </Box>
    );
};

// Chart for Privilege Escalations - pie chart showing success vs. failure distribution
const PrivilegeEscalationsChart = ({ timeRange }) => {
    const [data, setData] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const fetchData = async () => {
            try {
                setLoading(true);
                const startDate = startOfDay(subDays(new Date(), timeRange));
                const params = {};
                if (startDate) {
                    params.start_time = startDate.toISOString();
                }
                if (!params.start_time) {
                    params.lookback_hours = timeRange * 24;
                }
                const stats = await privilegeEscalationsApi.getStats(params);
                // success_count, failure_count
                const dataArr = [
                    { name: 'Successful', value: stats.success_count || 0 },
                    { name: 'Failed', value: stats.failure_count || 0 }
                ];
                setData(dataArr);
                setError(null);
            } catch (err) {
                console.error('Error fetching privilege escalation stats:', err);
                setError(err.message || 'Failed to load privilege escalation statistics');
            } finally {
                setLoading(false);
            }
        };
        fetchData();
    }, [timeRange]);

    if (loading) return <CircularProgress />;
    if (error) return <Typography color="error">{error}</Typography>;

    return (
        <Box sx={{ width: '100%', height: 320 }}>
            <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                    <Pie
                        data={data}
                        dataKey="value"
                        nameKey="name"
                        cx="50%"
                        cy="50%"
                        outerRadius={60}
                        label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                    >
                        {data.map((entry, index) => (
                            <Cell
                                key={`cell-${index}`}
                                fill={entry.name === 'Successful' ? SUCCESS_COLOR : FAILURE_COLOR}
                            />
                        ))}
                    </Pie>
                    <Tooltip formatter={(value, name) => [`${value} events`, name]} />
                    <Legend />
                </PieChart>
            </ResponsiveContainer>
        </Box>
    );
};

// Chart for Brute Force Attempts - bar chart showing blocked vs. unblocked attempts
const BruteForceAttemptsChart = ({ timeRange }) => {
    const [data, setData] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const fetchData = async () => {
            try {
                setLoading(true);
                const startDate = startOfDay(subDays(new Date(), timeRange));
                const params = {};
                if (startDate) {
                    params.start_time = startDate.toISOString();
                }
                if (!params.start_time) {
                    params.lookback_hours = timeRange * 24;
                }
                const stats = await bruteForceApi.getStats(params);
                // blocked_count, unblocked_count
                const dataArr = [
                    { name: 'Blocked', value: stats.blocked_count || 0 },
                    { name: 'Unblocked', value: stats.unblocked_count || 0 }
                ];
                setData(dataArr);
                setError(null);
            } catch (err) {
                console.error('Error fetching brute force attempt stats:', err);
                setError(err.message || 'Failed to load brute force attempt statistics');
            } finally {
                setLoading(false);
            }
        };
        fetchData();
    }, [timeRange]);

    if (loading) return <CircularProgress />;
    if (error) return <Typography color="error">{error}</Typography>;

    return (
        <Box sx={{ width: '100%', height: 320 }}>
            <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <Tooltip formatter={(value, name) => [`${value} attempts`, name]} />
                    <Legend />
                    <Bar dataKey="value" name="Attempts" fill="#8884d8" />
                </BarChart>
            </ResponsiveContainer>
        </Box>
    );
};

const LogAnalytics = () => {
    const [timeRange, setTimeRange] = useState(7); // Default to 7 days

    return (

        <Box>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 4 }}>
                <Typography>
                    Log Analytics Dashboard
                </Typography>
                <TimeRangeSelector timeRange={timeRange} setTimeRange={setTimeRange} />
            </Box>
            <Grid>
                {/* SSH Events Chart */}
                <Grid item xs={12} md={6}>
                    <Paper>
                        <Typography>
                            SSH Login Events
                        </Typography>
                        <Divider sx={{ mb: 2 }} />

                        <SSHEventsChart timeRange={timeRange} />
                    </Paper>
                </Grid>
                {/* Command Executions Chart */}
                <Grid>
                    <Paper>
                        <Typography>
                            Command Risk Distribution
                        </Typography>
                        <Divider sx={{ mb: 2 }} />

                        <CommandExecutionsChart timeRange={timeRange} />
                    </Paper>
                </Grid>
                {/* Privilege Escalations Chart */}
                <Grid>
                    <Paper>
                        <Typography>
                            Privilege Escalation Outcomes
                        </Typography>
                        <Divider sx={{ mb: 2 }} />

                        <PrivilegeEscalationsChart timeRange={timeRange} />
                    </Paper>
                </Grid>
                {/* Brute Force Attempts Chart */}
                <Grid>
                    <Paper>
                        <Typography>
                            Brute Force Attempts
                        </Typography>
                        <Divider sx={{ mb: 2 }} />

                        <BruteForceAttemptsChart timeRange={timeRange} />
                    </Paper>
                </Grid>
            </Grid>
        </Box>
    );
};

export default LogAnalytics;