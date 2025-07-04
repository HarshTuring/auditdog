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
    Chip
} from '@mui/material';
import { useSSHEvents } from '../hooks/useSSHEvents';
import { format } from 'date-fns';

const SSHEvents = () => {
    // Filter state
    const [filters, setFilters] = useState({
        username: '',
        source_ip: '',
        event_type: '',
        auth_method: '',
        success: ''
    });

    // Pagination state
    const [page, setPage] = useState(0);
    const [rowsPerPage, setRowsPerPage] = useState(100);

    // Fetch data using our custom hook
    const { events, loading, error, totalCount, refetch } = useSSHEvents(
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
        // Clear empty filters before sending to backend
        const cleanedFilters = {};
        Object.entries(filters).forEach(([key, value]) => {
            if (value !== '') {
                cleanedFilters[key] = value;
            }
        });

        setPage(0); // Reset to first page when applying filters
        refetch();
    };

    // Handle resetting filters
    const handleResetFilters = () => {
        setFilters({
            username: '',
            source_ip: '',
            event_type: '',
            auth_method: '',
            success: ''
        });
        setPage(0);
        refetch();
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

    // Format event type for display
    const formatEventType = (eventType) => {
        if (!eventType) return 'N/A';

        return eventType
            .split('_')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
    };

    return (
        <Box>
            <Typography>
                SSH Events
            </Typography>
            {/* Filters */}
            <Paper sx={{ p: 2, mb: 3 }}>
                <Grid>
                    <Grid item xs={12} sm={6} lg={3}>
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
                            label="Source IP"
                            name="source_ip"
                            value={filters.source_ip}
                            onChange={handleFilterChange}
                            size="small"
                        />
                    </Grid>
                    <Grid>
                        <FormControl sx={{ minWidth: 180 }}>
                            <InputLabel>
                                Event Type

                            </InputLabel>
                            <Select>
                                <MenuItem>
                                    All

                                </MenuItem>
                                <MenuItem>
                                    Login Success

                                </MenuItem>
                                <MenuItem>
                                    Login Failure

                                </MenuItem>
                                <MenuItem>
                                    Logout

                                </MenuItem>
                                <MenuItem>
                                    Session Open

                                </MenuItem>
                                <MenuItem>
                                    Session Close

                                </MenuItem>
                                <MenuItem>
                                    Authentication Attempt

                                </MenuItem>
                            </Select>
                        </FormControl>
                    </Grid>
                    <Grid>
                        <FormControl sx={{ minWidth: 180 }}>
                            <InputLabel>
                                Auth Method

                            </InputLabel>
                            <Select>
                                <MenuItem>
                                    All

                                </MenuItem>
                                <MenuItem>
                                    Password

                                </MenuItem>
                                <MenuItem>
                                    Public Key

                                </MenuItem>
                                <MenuItem>
                                    Keyboard Interactive

                                </MenuItem>
                                <MenuItem>
                                    GSSAPI

                                </MenuItem>
                                <MenuItem>
                                    Host Based

                                </MenuItem>
                                <MenuItem>
                                    None

                                </MenuItem>
                            </Select>
                        </FormControl>
                    </Grid>
                    <Grid>
                        <FormControl sx={{ minWidth: 180 }}>
                            <InputLabel>
                                Status

                            </InputLabel>
                            <Select>
                                <MenuItem>
                                    All

                                </MenuItem>
                                <MenuItem>
                                    Success

                                </MenuItem>
                                <MenuItem>
                                    Failed

                                </MenuItem>
                            </Select>
                        </FormControl>
                    </Grid>
                    <Grid item xs={12}>
                        <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 2 }}>
                            <Button onClick={handleResetFilters}>
                                Reset Filters
                            </Button>
                            <Button onClick={handleApplyFilters}>
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
                                Event Type

                            </TableCell>
                            <TableCell>
                                Timestamp

                            </TableCell>
                            <TableCell>
                                Username

                            </TableCell>
                            <TableCell>
                                Source IP

                            </TableCell>
                            <TableCell>
                                Auth Method

                            </TableCell>
                            <TableCell>
                                Status

                            </TableCell>
                            <TableCell>
                                Session ID

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
                                    No SSH events found

                                </TableCell>
                            </TableRow>
                        ) : (
                            events.map((event) => (
                                <TableRow>
                                    <TableCell>
                                        {formatEventType(event.event_type)}

                                    </TableCell>
                                    <TableCell>
                                        {formatTimestamp(event.timestamp)}

                                    </TableCell>
                                    <TableCell>
                                        {event.username || 'N/A'}

                                    </TableCell>
                                    <TableCell>
                                        {event.source_ip || 'N/A'}

                                    </TableCell>
                                    <TableCell>
                                        {event.auth_method || 'N/A'}

                                    </TableCell>
                                    <TableCell>
                                        <Chip
                                            label={event.success ? 'Success' : 'Failed'}
                                            color={event.success ? 'success' : 'error'}
                                            size="small"
                                        />

                                    </TableCell>
                                    <TableCell>
                                        {event.session_id || 'N/A'}

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

export default SSHEvents;