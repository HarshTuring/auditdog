import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import BruteForceAttempts from '../BruteForceAttempts';
import { useBruteForceAttempts } from '../../hooks/useBruteForceAttempts';

// Mock the custom hook
jest.mock('../../hooks/useBruteForceAttempts', () => ({
  useBruteForceAttempts: jest.fn(),
}));

describe('BruteForceAttempts Component', () => {
  beforeEach(() => {
    // Reset the mock before each test
    useBruteForceAttempts.mockReturnValue({
      events: [],
      loading: false,
      error: null,
      totalCount: 0,
      refetch: jest.fn(),
    });
  });

  test('renders the component without crashing', () => {
    render(<BruteForceAttempts />);
  });

  test('displays the main title', () => {
    render(<BruteForceAttempts />);
    expect(screen.getByText('Brute Force Attempts')).toBeInTheDocument();
  });

  test('renders the "Apply Filters" and "Reset Filters" buttons', () => {
    render(<BruteForceAttempts />);
    expect(screen.getByRole('button', { name: /apply filters/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /reset filters/i })).toBeInTheDocument();
  });

  test('shows a loading message when loading is true', () => {
    useBruteForceAttempts.mockReturnValue({ loading: true, events: [], error: null });
    render(<BruteForceAttempts />);
    expect(screen.getByText('Loading...')).toBeInTheDocument();
  });

  test('shows an error message when an error is present', () => {
    useBruteForceAttempts.mockReturnValue({ loading: false, events: [], error: 'Failed to fetch data' });
    render(<BruteForceAttempts />);
    expect(screen.getByText('Error: Failed to fetch data')).toBeInTheDocument();
  });

  test('shows "No brute force attempts found" when there are no events', () => {
    useBruteForceAttempts.mockReturnValue({ loading: false, events: [], error: null });
    render(<BruteForceAttempts />);
    expect(screen.getByText('No brute force attempts found')).toBeInTheDocument();
  });
});
