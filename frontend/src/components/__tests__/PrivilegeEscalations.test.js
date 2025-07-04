import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import PrivilegeEscalations from '../PrivilegeEscalations';
import { usePrivilegeEscalations } from '../../hooks/usePrivilegeEscalations';

// Mock the custom hook
jest.mock('../../hooks/usePrivilegeEscalations', () => ({
  usePrivilegeEscalations: jest.fn(),
}));

describe('PrivilegeEscalations Component', () => {
  beforeEach(() => {
    // Reset the mock before each test
    usePrivilegeEscalations.mockReturnValue({
      events: [],
      loading: false,
      error: null,
      totalCount: 0,
      refetch: jest.fn(),
    });
  });

  test('renders the component without crashing', () => {
    render(<PrivilegeEscalations />);
  });

  test('displays the main title', () => {
    render(<PrivilegeEscalations />);
    expect(screen.getByText('Privilege Escalation Events')).toBeInTheDocument();
  });

  test('renders the "Apply Filters" and "Reset Filters" buttons', () => {
    render(<PrivilegeEscalations />);
    expect(screen.getByRole('button', { name: /apply filters/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /reset filters/i })).toBeInTheDocument();
  });

  test('shows a loading message when loading is true', () => {
    usePrivilegeEscalations.mockReturnValue({ loading: true, events: [], error: null });
    render(<PrivilegeEscalations />);
    expect(screen.getByText('Loading...')).toBeInTheDocument();
  });

  test('shows an error message when an error is present', () => {
    usePrivilegeEscalations.mockReturnValue({ loading: false, events: [], error: 'Failed to fetch data' });
    render(<PrivilegeEscalations />);
    expect(screen.getByText('Error: Failed to fetch data')).toBeInTheDocument();
  });

  test('shows "No privilege escalation events found" when there are no events', () => {
    usePrivilegeEscalations.mockReturnValue({ loading: false, events: [], error: null });
    render(<PrivilegeEscalations />);
    expect(screen.getByText('No privilege escalation events found')).toBeInTheDocument();
  });
});
