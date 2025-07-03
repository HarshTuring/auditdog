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
import { usePrivilegeEscalations } from '../hooks/usePrivilegeEscalations';
import { format } from 'date-fns';

const PrivilegeEscalations = () => {
    // Filter state
    const [filters, setFilters] = useState({
        username: '',
        target_user: '',
        method: '',
        success: ''
    });

    // Pagination state
    const [page, setPage] = useState(0);
    const [rowsPerPage, setRowsPerPage] = useState(100);

    // Fetch data using our custom hook
    const { events, loading, error, totalCount, refetch } = usePrivilegeEscalations(
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
        setPage(0);
        refetch();
    };

    // Handle resetting filters
    const handleResetFilters = () => {
        setFilters({
            username: '',
            target_user: '',
            method: '',
            success: ''
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

    return (
        <Box>
            <Typography>
                Privilege Escalation Events
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
                            label="Target User"
                            name="target_user"
                            value={filters.target_user}
                            onChange={handleFilterChange}
                            size="small"
                        />
                    </Grid>
                    <Grid>
                        <FormControl>
                            <InputLabel>
                                Method

                            </InputLabel>
                            <Select>
                                <MenuItem>
                                    All

                                </MenuItem>
                                <MenuItem>
                                    Sudo

                                </MenuItem>
                                <MenuItem>
                                    Su

                                </MenuItem>
                                <MenuItem>
                                    Setuid

                                </MenuItem>
                                <MenuItem>
                                    Pkexec

                                </MenuItem>
                                <MenuItem>
                                    Doas

                                </MenuItem>
                                <MenuItem>
                                    Other

                                </MenuItem>
                            </Select>
                        </FormControl>
                    </Grid>
                    <Grid>
                        <FormControl>
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
                                Timestamp

                            </TableCell>
                            <TableCell>
                                Username

                            </TableCell>
                            <TableCell>
                                Target User

                            </TableCell>
                            <TableCell>
                                Method

                            </TableCell>
                            <TableCell>
                                Command

                            </TableCell>
                            <TableCell>
                                Source IP

                            </TableCell>
                            <TableCell>
                                Status

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
                                    No privilege escalation events found

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
                                        {event.target_user || 'N/A'}

                                    </TableCell>
                                    <TableCell>
                                        {event.method || 'N/A'}

                                    </TableCell>
                                    <TableCell>
                                        {event.command ? (
                                            <Tooltip>
                                                <Typography>
                                                    {event.command}
                                                </Typography>
                                            </Tooltip>
                                        ) : 'N/A'}
                                    </TableCell>
                                    <TableCell>
                                        {event.source_ip || 'N/A'}

                                    </TableCell>
                                    <TableCell>
                                        <Chip
                                            label={event.success ? 'Success' : 'Failed'}
                                            color={event.success ? 'success' : 'error'}
                                            size="small"
                                        />

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

export default PrivilegeEscalations;