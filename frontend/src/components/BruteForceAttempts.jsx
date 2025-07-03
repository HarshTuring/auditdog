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
import { useBruteForceAttempts } from '../hooks/useBruteForceAttempts';
import { format } from 'date-fns';

const BruteForceAttempts = () => {
    // Filter state
    const [filters, setFilters] = useState({
        source_ip: '',
        target_username: '',
        blocked: ''
    });

    // Pagination state
    const [page, setPage] = useState(0);
    const [rowsPerPage, setRowsPerPage] = useState(100);

    // Fetch data using our custom hook
    const { events, loading, error, totalCount, refetch } = useBruteForceAttempts(
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
            source_ip: '',
            target_username: '',
            blocked: ''
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
                Brute Force Attempts
            </Typography>
            {/* Filters */}
            <Paper sx={{ p: 2, mb: 3 }}>
                <Grid>
                    <Grid item xs={12} sm={4}>
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
                        <TextField
                            fullWidth
                            label="Target Username"
                            name="target_username"
                            value={filters.target_username}
                            onChange={handleFilterChange}
                            size="small"
                        />
                    </Grid>
                    <Grid>
                        <FormControl>
                            <InputLabel>
                                Blocked

                            </InputLabel>
                            <Select>
                                <MenuItem>
                                    All

                                </MenuItem>
                                <MenuItem>
                                    Yes

                                </MenuItem>
                                <MenuItem>
                                    No

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
                                Source IP

                            </TableCell>
                            <TableCell>
                                Target Username

                            </TableCell>
                            <TableCell>
                                Attempt Count

                            </TableCell>
                            <TableCell>
                                First Attempt

                            </TableCell>
                            <TableCell>
                                Last Attempt

                            </TableCell>
                            <TableCell>
                                Blocked

                            </TableCell>
                            <TableCell>
                                Block Duration

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
                                    No brute force attempts found

                                </TableCell>
                            </TableRow>
                        ) : (
                            events.map((event) => (
                                <TableRow>
                                    <TableCell>
                                        {event.source_ip || 'N/A'}

                                    </TableCell>
                                    <TableCell>
                                        {event.target_username || 'N/A'}

                                    </TableCell>
                                    <TableCell>
                                        {event.attempt_count || 'N/A'}

                                    </TableCell>
                                    <TableCell>
                                        {formatTimestamp(event.first_attempt)}

                                    </TableCell>
                                    <TableCell>
                                        {formatTimestamp(event.last_attempt)}

                                    </TableCell>
                                    <TableCell>
                                        <Chip
                                            label={event.blocked ? 'Yes' : 'No'}
                                            color={event.blocked ? 'error' : 'default'}
                                            size="small"
                                        />

                                    </TableCell>
                                    <TableCell>
                                        {event.block_duration ? `${event.block_duration} seconds` : 'N/A'}
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

export default BruteForceAttempts;