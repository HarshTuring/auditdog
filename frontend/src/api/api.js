import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api/v1';

// Create axios instance
const apiClient = axios.create({
    baseURL: API_BASE_URL,
    headers: {
        'Content-Type': 'application/json',
    },
});

// SSH Events API
export const sshEventsApi = {
    // Get all SSH events with optional filtering
    async getEvents(params = {}) {
        try {
            const response = await apiClient.get('/ssh/events', { params });
            return response.data;
        } catch (error) {
            console.error('Error fetching SSH events:', error);
            throw error;
        }
    },

    // Get a specific SSH event by ID
    async getEvent(id) {
        try {
            const response = await apiClient.get(`/ssh/events/${id}`);
            return response.data;
        } catch (error) {
            console.error(`Error fetching SSH event with id ${id}:`, error);
            throw error;
        }
    },

    // Get SSH events statistics
    async getStats(params = {}) {
        try {
            const response = await apiClient.get('/ssh/events/stats', { params });
            return response.data;
        } catch (error) {
            console.error('Error fetching SSH events statistics:', error);
            throw error;
        }
    },
};

// Command Executions API
export const commandExecutionsApi = {
    // Get all command execution events with optional filtering
    async getEvents(params = {}) {
        try {
            const response = await apiClient.get('/command-executions', { params });
            return response.data;
        } catch (error) {
            console.error('Error fetching command executions:', error);
            throw error;
        }
    },

    // Get a specific command execution by ID
    async getEvent(id) {
        try {
            const response = await apiClient.get(`/command-executions/${id}`);
            return response.data;
        } catch (error) {
            console.error(`Error fetching command execution with id ${id}:`, error);
            throw error;
        }
    },

    // Get command executions statistics
    async getStats(params = {}) {
        try {
            const response = await apiClient.get('/command-executions/stats', { params });
            return response.data;
        } catch (error) {
            console.error('Error fetching command executions statistics:', error);
            throw error;
        }
    },
};

// Privilege Escalation API
export const privilegeEscalationsApi = {
    // Get all privilege escalation events
    async getEvents(params = {}) {
        try {
            const response = await apiClient.get('/privilege-escalations', { params });
            return response.data;
        } catch (error) {
            console.error('Error fetching privilege escalations:', error);
            throw error;
        }
    },

    // Get a specific privilege escalation by ID
    async getEvent(id) {
        try {
            const response = await apiClient.get(`/privilege-escalations/${id}`);
            return response.data;
        } catch (error) {
            console.error(`Error fetching privilege escalation with id ${id}:`, error);
            throw error;
        }
    },

    // Get privilege escalations statistics
    async getStats(params = {}) {
        try {
            const response = await apiClient.get('/privilege-escalations/stats', { params });
            return response.data;
        } catch (error) {
            console.error('Error fetching privilege escalations statistics:', error);
            throw error;
        }
    },
};

// Brute Force Attempts API
export const bruteForceApi = {
    // Get all brute force attempts
    async getEvents(params = {}) {
        try {
            const response = await apiClient.get('/brute-force', { params });
            return response.data;
        } catch (error) {
            console.error('Error fetching brute force attempts:', error);
            throw error;
        }
    },

    // Get a specific brute force attempt by ID
    async getEvent(id) {
        try {
            const response = await apiClient.get(`/brute-force/${id}`);
            return response.data;
        } catch (error) {
            console.error(`Error fetching brute force attempt with id ${id}:`, error);
            throw error;
        }
    },

    // Get brute force attempts statistics
    async getStats(params = {}) {
        try {
            const response = await apiClient.get('/brute-force/stats', { params });
            return response.data;
        } catch (error) {
            console.error('Error fetching brute force attempts statistics:', error);
            throw error;
        }
    },
};