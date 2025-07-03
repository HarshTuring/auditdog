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

// Chart for SSH events - line chart showing successful vs. failed logins over time
const SSHEventsChart = ({ timeRange }) => {
    const [data, setData] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const fetchData = async () => {
            try {
                setLoading(true);

                // Calculate the start date based on the selected time range
                const startDate = startOfDay(subDays(new Date(), timeRange));

                const params = {};
                if (startDate) {
                    params.start_time = startDate.toISOString();
                }
                if (!params.start_time) {
                    params.lookback_hours = timeRange * 24;
                }

                const stats = await sshEventsApi.getStats(params);

                // Process the data for the chart
                // For this example, we'll use mock data that simulates hourly stats
                const processedData = Array.from({ length: timeRange }).map((_, i) => {
                    const date = subDays(new Date(), timeRange - i - 1);
                    return {
                        date: format(date, 'MM/dd'),
                        successful: Math.floor(Math.random() * 30) + 5,  // Mock data
                        failed: Math.floor(Math.random() * 15) + 1       // Mock data
                    };
                });

                setData(processedData);
            } catch (err) {
                console.error('Error fetching SSH event stats:', err);
                setError(err.message || 'Failed to load SSH event statistics');
            } finally {
                setLoading(false);
            }
        };

        fetchData();
    }, [timeRange]);

    if (loading) return

    <CircularProgress />
        ;
    if (error) return

    <Typography>
        {error}

    </Typography>
        ;

    return (

        <ResponsiveContainer>
            <LineChart>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="date" />
                <YAxis />
                <Tooltip
                    formatter={(value, name) => [value, name === 'successful' ? 'Successful Logins' : 'Failed Logins']}
                    labelFormatter={(label) => `Date: ${label}`}
                />
                <Legend formatter={(value) => value === 'successful' ? 'Successful Logins' : 'Failed Logins'} />
                <Line type="monotone" dataKey="successful" stroke={SUCCESS_COLOR} activeDot={{ r: 8 }} name="successful" />

                <Line type="monotone" dataKey="failed" stroke={FAILURE_COLOR} name="failed" />
            </LineChart>
        </ResponsiveContainer>
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

                // Calculate the start date based on the selected time range
                const startDate = startOfDay(subDays(new Date(), timeRange));

                const params = {};
                if (startDate) {
                    params.start_time = startDate.toISOString();
                }
                if (!params.start_time) {
                    params.lookback_hours = timeRange * 24;
                }

                const stats = await commandExecutionsApi.getStats(params);

                // Mock data - this would be replaced with actual stats
                const processedData = [
                    { name: 'Critical', count: Math.floor(Math.random() * 10) },
                    { name: 'High', count: Math.floor(Math.random() * 25) + 5 },
                    { name: 'Medium', count: Math.floor(Math.random() * 40) + 20 },
                    { name: 'Low', count: Math.floor(Math.random() * 60) + 30 },
                    { name: 'Minimal', count: Math.floor(Math.random() * 80) + 40 }
                ];

                setData(processedData);
            } catch (err) {
                console.error('Error fetching command execution stats:', err);
                setError(err.message || 'Failed to load command execution statistics');
            } finally {
                setLoading(false);
            }
        };

        fetchData();
    }, [timeRange]);

    if (loading) return

    <CircularProgress />
        ;
    if (error) return

    <Typography>
        {error}

    </Typography>
        ;

    return (

        <ResponsiveContainer>
            <BarChart>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip formatter={(value) => [`${value} commands`, 'Count']} />
                <Legend />
                <Bar>
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

                // Calculate the start date based on the selected time range
                const startDate = startOfDay(subDays(new Date(), timeRange));

                const params = {};
                if (startDate) {
                    params.start_time = startDate.toISOString();
                }
                if (!params.start_time) {
                    params.lookback_hours = timeRange * 24;
                }

                const stats = await privilegeEscalationsApi.getStats(params);

                // Mock data - this would be replaced with actual stats
                const successCount = Math.floor(Math.random() * 75) + 25;
                const failureCount = Math.floor(Math.random() * 30) + 5;

                const processedData = [
                    { name: 'Successful', value: successCount },
                    { name: 'Failed', value: failureCount }
                ];

                setData(processedData);
            } catch (err) {
                console.error('Error fetching privilege escalation stats:', err);
                setError(err.message || 'Failed to load privilege escalation statistics');
            } finally {
                setLoading(false);
            }
        };

        fetchData();
    }, [timeRange]);

    if (loading) return

    <CircularProgress />
        ;
    if (error) return

    <Typography>
        {error}

    </Typography>
        ;

    return (

        <ResponsiveContainer>
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

                // Calculate the start date based on the selected time range
                const startDate = startOfDay(subDays(new Date(), timeRange));

                const params = {};
                if (startDate) {
                    params.start_time = startDate.toISOString();
                }
                if (!params.start_time) {
                    params.lookback_hours = timeRange * 24;
                }

                const stats = await bruteForceApi.getStats(params);

                // Mock data - this would be replaced with actual stats from the API response
                const processedData = Array.from({ length: Math.min(7, timeRange) }).map((_, i) => {
                    const date = subDays(new Date(), Math.min(7, timeRange) - i - 1);
                    return {
                        date: format(date, 'MM/dd'),
                        blocked: Math.floor(Math.random() * 20) + 5,  // Mock data
                        attempts: Math.floor(Math.random() * 50) + 20  // Mock data for total attempts
                    };
                });

                setData(processedData);
            } catch (err) {
                console.error('Error fetching brute force attempt stats:', err);
                setError(err.message || 'Failed to load brute force attempt statistics');
            } finally {
                setLoading(false);
            }
        };

        fetchData();
    }, [timeRange]);

    if (loading) return

    <CircularProgress />
        ;
    if (error) return

    <Typography>
        {error}

    </Typography>
        ;

    return (

        <ResponsiveContainer>
            <BarChart>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="date" />
                <YAxis />
                <Tooltip formatter={(value, name) => [`${value} ${name}`, name.charAt(0).toUpperCase() + name.slice(1)]} />
                <Legend />
                <Bar dataKey="attempts" name="Total Attempts" fill="#8884d8" />
                <Bar dataKey="blocked" name="Blocked" fill="#FF5733" />
            </BarChart>
        </ResponsiveContainer>
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