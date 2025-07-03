import { useState, useEffect, useCallback } from 'react';
import { sshEventsApi } from '../api/api';

export function useSSHEvents(
    filters = {},
    page = 0,
    pageSize = 100
) {
    const [events, setEvents] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [totalCount, setTotalCount] = useState(0);

    const fetchEvents = useCallback(async () => {
        try {
            setLoading(true);
            const params = {
                ...filters,
                skip: page * pageSize,
                limit: pageSize
            };

            const data = await sshEventsApi.getEvents(params);
            setEvents(data || []);
            setTotalCount(data?.length || 0); // API doesn't seem to provide total count
            setError(null);
        } catch (err) {
            setError(err.message || 'Failed to fetch SSH events');
            console.error('Error in useSSHEvents:', err);
        } finally {
            setLoading(false);
        }
    }, [filters, page, pageSize]);

    useEffect(() => {
        fetchEvents();
    }, [fetchEvents]);

    return { events, loading, error, totalCount, refetch: fetchEvents };
}