import React from 'react';
import { Box, Grid, Paper, Typography, Button } from '@mui/material';
import { useNavigate } from 'react-router-dom';

const DashboardCard = ({ title, description, linkTo, linkText }) => {
    const navigate = useNavigate();

    return (
        <Paper>
            <Typography>
                {title}
            </Typography>
            <Typography>
                {description}
            </Typography>
            <Button
                onClick={() => navigate(linkTo)}
            >
                {linkText}

            </Button>
        </Paper>
    );
};

const Dashboard = () => {
    return (

        <Box>
            <Typography>
                AuditDog Dashboard
            </Typography>
            <Typography>
                Welcome to the AuditDog monitoring system. View and analyze security events from your Linux servers.
            </Typography>
            <Grid>
                <Grid item xs={12} md={6} lg={3}>
                    <DashboardCard
                        title="SSH Events"
                        description="View SSH login events including successful and failed authentication attempts."
                        linkTo="/ssh-events"
                        linkText="View SSH Events"
                    />

                </Grid>
                <Grid>
                    <DashboardCard
                        title="Command Executions"
                        description="Monitor commands executed on your servers with risk assessment."
                        linkTo="/command-executions"
                        linkText="View Commands"
                    />

                </Grid>
                <Grid>
                    <DashboardCard
                        title="Privilege Escalations"
                        description="Track privilege escalation attempts through sudo, su, and other methods."
                        linkTo="/privilege-escalations"
                        linkText="View Escalations"
                    />

                </Grid>
                <Grid>
                    <DashboardCard
                        title="Brute Force Attempts"
                        description="Monitor SSH brute force attacks and IP blocking events."
                        linkTo="/brute-force"
                        linkText="View Attempts"
                    />

                </Grid>
            </Grid>
        </Box>
    );
};

export default Dashboard;