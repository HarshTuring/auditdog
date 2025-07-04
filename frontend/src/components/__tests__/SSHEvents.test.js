import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import SSHEvents from '../SSHEvents';
import { useSSHEvents } from '../../hooks/useSSHEvents';

// Mock the custom hook
jest.mock('../../hooks/useSSHEvents', () => ({
  useSSHEvents: jest.fn(),
}));

describe('SSHEvents Component', () => {
  beforeEach(() => {
    // Reset the mock before each test
    useSSHEvents.mockReturnValue({
      events: [],
      loading: false,
      error: null,
      totalCount: 0,
      refetch: jest.fn(),
    });
  });

  test('renders the component without crashing', () => {
    render(<SSHEvents />);
  });

  test('displays the main title', () => {
    render(<SSHEvents />);
    expect(screen.getByText('SSH Events')).toBeInTheDocument();
  });

  test('renders the "Apply Filters" and "Reset Filters" buttons', () => {
    render(<SSHEvents />);
    expect(screen.getByRole('button', { name: /apply filters/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /reset filters/i })).toBeInTheDocument();
  });

  test('shows a loading message when loading is true', () => {
    useSSHEvents.mockReturnValue({ loading: true, events: [], error: null });
    render(<SSHEvents />);
    expect(screen.getByText('Loading...')).toBeInTheDocument();
  });

  test('shows an error message when an error is present', () => {
    useSSHEvents.mockReturnValue({ loading: false, events: [], error: 'Failed to fetch data' });
    render(<SSHEvents />);
    expect(screen.getByText('Error: Failed to fetch data')).toBeInTheDocument();
  });

  test('shows "No SSH events found" when there are no events', () => {
    useSSHEvents.mockReturnValue({ loading: false, events: [], error: null });
    render(<SSHEvents />);
    expect(screen.getByText('No SSH events found')).toBeInTheDocument();
  });
});
