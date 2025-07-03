import React, { useState } from 'react';
import {
    Box,
    Paper,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    TablePagination,
    Typography,
    TextField,
    FormControl,
    InputLabel,
    Select,
    MenuItem,
    Grid,
    Button,
    Chip,
    Tooltip
} from '@mui/material';
import { useCommandExecutions } from '../hooks/useCommandExecutions';
import { format } from 'date-fns';

const CommandExecutions = () => {
    // Filter state
    const [filters, setFilters] = useState({
        username: '',
        host: '',
        command: '',
        risk_level: ''
    });

    // Pagination state
    const [page, setPage] = useState(0);
    const [rowsPerPage, setRowsPerPage] = useState(100);

    // Fetch data using our custom hook
    const { events, loading, error, totalCount, refetch } = useCommandExecutions(
        filters,
        page,
        rowsPerPage
    );

    // Handle filter changes
    const handleFilterChange = (e) => {
        const { name, value } = e.target;
        setFilters(prev => ({
            ...prev,
            [name]: value
        }));
    };

    // Handle applying filters
    const handleApplyFilters = () => {
        setPage(0); // Reset to first page when applying filters
        refetch();
    };

    // Handle resetting filters
    const handleResetFilters = () => {
        setFilters({
            username: '',
            host: '',
            command: '',
            risk_level: ''
        });
        setPage(0);
    };

    // Pagination handlers
    const handleChangePage = (event, newPage) => {
        setPage(newPage);
    };

    const handleChangeRowsPerPage = (event) => {
        setRowsPerPage(parseInt(event.target.value, 10));
        setPage(0);
    };

    // Format timestamp
    const formatTimestamp = (timestamp) => {
        try {
            if (!timestamp) return 'N/A';
            return format(new Date(timestamp), 'yyyy-MM-dd HH:mm:ss');
        } catch (err) {
            console.error('Error formatting timestamp:', err);
            return timestamp || 'N/A';
        }
    };

    // Get color for risk level
    const getRiskLevelColor = (riskLevel) => {
        switch (riskLevel?.toLowerCase()) {
            case 'critical':
                return 'error';
            case 'high':
                return 'error';
            case 'medium':
                return 'warning';
            case 'low':
                return 'success';
            case 'minimal':
                return 'info';
            default:
                return 'default';
        }
    };

    return (
        <Box>
            <Typography>
                Command Execution Events
            </Typography>
            {/* Filters */}
            <Paper sx={{ p: 2, mb: 3 }}>
                <Grid>
                    <Grid item xs={12} sm={6} md={3}>
                        <TextField
                            fullWidth
                            label="Username"
                            name="username"
                            value={filters.username}
                            onChange={handleFilterChange}
                            size="small"
                        />
                    </Grid>
                    <Grid>
                        <TextField
                            fullWidth
                            label="Host"
                            name="host"
                            value={filters.host}
                            onChange={handleFilterChange}
                            size="small"
                        />
                    </Grid>
                    <Grid>
                        <TextField
                            fullWidth
                            label="Command"
                            name="command"
                            value={filters.command}
                            onChange={handleFilterChange}
                            size="small"
                        />
                    </Grid>
                    <Grid>
                        <FormControl>
                            <InputLabel>
                                Risk Level

                            </InputLabel>
                            <Select>
                                <MenuItem>
                                    All

                                </MenuItem>
                                <MenuItem>
                                    Critical

                                </MenuItem>
                                <MenuItem>
                                    High

                                </MenuItem>
                                <MenuItem>
                                    Medium

                                </MenuItem>
                                <MenuItem>
                                    Low

                                </MenuItem>
                                <MenuItem>
                                    Minimal

                                </MenuItem>
                            </Select>
                        </FormControl>
                    </Grid>
                    <Grid item xs={12}>
                        <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 2 }}>
                            <Button>
                                Reset Filters
                            </Button>
                            <Button>
                                Apply Filters
                            </Button>
                        </Box>
                    </Grid>
                </Grid>
            </Paper>

            {/* Error display */}
            {error && (
                <Typography>
                    Error: {error}
                </Typography>
            )}

            {/* Data table */}
            <TableContainer>
                <Table>
                    <TableHead>
                        <TableRow>
                            <TableCell>
                                Timestamp

                            </TableCell>
                            <TableCell>
                                Username

                            </TableCell>
                            <TableCell>
                                Host

                            </TableCell>
                            <TableCell>
                                Command

                            </TableCell>
                            <TableCell>
                                Risk Level

                            </TableCell>
                            <TableCell>
                                Exit Code

                            </TableCell>
                            <TableCell>
                                Working Directory

                            </TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {loading ? (
                            <TableRow>
                                <TableCell>
                                    Loading...

                                </TableCell>
                            </TableRow>
                        ) : events.length === 0 ? (
                            <TableRow>
                                <TableCell>
                                    No command execution events found

                                </TableCell>
                            </TableRow>
                        ) : (
                            events.map((event) => (
                                <TableRow>
                                    <TableCell>
                                        {formatTimestamp(event.timestamp)}

                                    </TableCell>
                                    <TableCell>
                                        {event.username || 'N/A'}

                                    </TableCell>
                                    <TableCell>
                                        {event.host || 'N/A'}

                                    </TableCell>
                                    <TableCell>
                                        <Tooltip>
                                            <Typography>
                                                {event.command || 'N/A'}
                                            </Typography>
                                        </Tooltip>
                                    </TableCell>
                                    <TableCell>
                                        {event.risk_level && (
                                            <Chip
                                                label={event.risk_level}
                                                color={getRiskLevelColor(event.risk_level)}
                                                size="small"
                                            />

                                        )}
                                    </TableCell>
                                    <TableCell>
                                        {event.exit_code !== undefined ? event.exit_code : 'N/A'}

                                    </TableCell>
                                    <TableCell>
                                        {event.working_directory || 'N/A'}

                                    </TableCell>
                                </TableRow>
                            ))
                        )}
                    </TableBody>
                </Table>
                <TablePagination
                    rowsPerPageOptions={[25, 50, 100]}
                    component="div"
                    count={totalCount}
                    rowsPerPage={rowsPerPage}
                    page={page}
                    onPageChange={handleChangePage}
                    onRowsPerPageChange={handleChangeRowsPerPage}
                />
            </TableContainer>
        </Box>
    );
};

export default CommandExecutions;