import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import CommandExecutions from '../CommandExecutions';
import { useCommandExecutions } from '../../hooks/useCommandExecutions';

// Mock the custom hook
jest.mock('../../hooks/useCommandExecutions', () => ({
  useCommandExecutions: jest.fn(),
}));

describe('CommandExecutions Component', () => {
  beforeEach(() => {
    // Reset the mock before each test
    useCommandExecutions.mockReturnValue({
      events: [],
      loading: false,
      error: null,
      totalCount: 0,
      refetch: jest.fn(),
    });
  });

  test('renders the component without crashing', () => {
    render(<CommandExecutions />);
  });

  test('displays the main title', () => {
    render(<CommandExecutions />);
    expect(screen.getByText('Command Execution Events')).toBeInTheDocument();
  });

  test('renders the "Apply Filters" and "Reset Filters" buttons', () => {
    render(<CommandExecutions />);
    expect(screen.getByRole('button', { name: /apply filters/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /reset filters/i })).toBeInTheDocument();
  });

  test('shows a loading message when loading is true', () => {
    useCommandExecutions.mockReturnValue({ loading: true, events: [], error: null });
    render(<CommandExecutions />);
    expect(screen.getByText('Loading...')).toBeInTheDocument();
  });

  test('shows an error message when an error is present', () => {
    useCommandExecutions.mockReturnValue({ loading: false, events: [], error: 'Failed to fetch data' });
    render(<CommandExecutions />);
    expect(screen.getByText('Error: Failed to fetch data')).toBeInTheDocument();
  });

  test('shows "No command execution events found" when there are no events', () => {
    useCommandExecutions.mockReturnValue({ loading: false, events: [], error: null });
    render(<CommandExecutions />);
    expect(screen.getByText('No command execution events found')).toBeInTheDocument();
  });
});
