import { useState, useEffect, useCallback } from 'react';
import { commandExecutionsApi } from '../api/api';

export function useCommandExecutions(
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

            const data = await commandExecutionsApi.getEvents(params);
            setEvents(data || []);
            setTotalCount(data?.length || 0);
            setError(null);
        } catch (err) {
            setError(err.message || 'Failed to fetch command executions');
            console.error('Error in useCommandExecutions:', err);
        } finally {
            setLoading(false);
        }
    }, [filters, page, pageSize]);

    useEffect(() => {
        fetchEvents();
    }, [fetchEvents]);

    return { events, loading, error, totalCount, refetch: fetchEvents };
}