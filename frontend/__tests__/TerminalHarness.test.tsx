/**
 * Tests for TerminalHarness component.
 *
 * The component drives a timed log-sequence via setTimeout. We use
 * jest.useFakeTimers() to run all timers synchronously, making every
 * state update deterministic.
 */

import React from "react";
import { render, screen, act, fireEvent } from "@testing-library/react";
import "@testing-library/jest-dom";
import TerminalHarness from "@/components/TerminalHarness";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Advance time past the longest timeout in the log sequence (~15 100 ms)
 * and flush React state.
 *
 * We deliberately avoid jest.runAllTimers() because TerminalHarness registers
 * a setInterval for the blinking cursor that fires indefinitely — runAllTimers
 * tries to drain every queued timer and hits the 100 000-timer safety guard.
 * Advancing by a fixed amount is safe and deterministic.
 */
async function flushTimers(): Promise<void> {
  await act(async () => {
    jest.advanceTimersByTime(16_000);
  });
}

// ---------------------------------------------------------------------------
// Setup / teardown
// ---------------------------------------------------------------------------

beforeEach(() => {
  jest.useFakeTimers();
});

afterEach(() => {
  jest.useRealTimers();
});

// ---------------------------------------------------------------------------
// Structural rendering
// ---------------------------------------------------------------------------

describe("TerminalHarness — structure", () => {
  it("renders without crashing with default props", () => {
    render(<TerminalHarness />);
    expect(screen.getByText(/graphward-agent/i)).toBeInTheDocument();
  });

  it("renders the Rerun button", () => {
    render(<TerminalHarness />);
    expect(
      screen.getByRole("button", { name: /rerun/i })
    ).toBeInTheDocument();
  });

  it("displays nodeCount in the status bar", () => {
    render(<TerminalHarness nodeCount={42} />);
    expect(screen.getByText(/42 nodes/i)).toBeInTheDocument();
  });

  it("displays cveCount in the status bar", () => {
    render(<TerminalHarness cveCount={7} />);
    expect(screen.getByText(/7 cve flags/i)).toBeInTheDocument();
  });

  it("displays testsPassed/testsTotal in the status bar", () => {
    render(<TerminalHarness testsPassed={10} testsTotal={12} />);
    expect(screen.getByText("10/12 tests")).toBeInTheDocument();
  });

  it("shows Running indicator before sequence completes", async () => {
    render(<TerminalHarness nodeCount={10} testsTotal={5} testsPassed={5} />);
    // After mount, sequence starts; before all timers fire it should be running
    await act(async () => {
      jest.advanceTimersByTime(100);
    });
    expect(screen.getByText(/running/i)).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// Log sequence execution
// ---------------------------------------------------------------------------

describe("TerminalHarness — log sequence", () => {
  it("emits SYSTEM entry with engine version after mount", async () => {
    render(<TerminalHarness />);
    await flushTimers();
    expect(
      screen.getByText(/GraphWard Autonomous Remediation Engine v1\.0\.0/i)
    ).toBeInTheDocument();
  });

  it("emits STEP 1/7 entry", async () => {
    render(<TerminalHarness />);
    await flushTimers();
    expect(screen.getByText(/STEP 1\/7/i)).toBeInTheDocument();
  });

  it("emits STEP 7/7 at sequence end", async () => {
    render(<TerminalHarness />);
    await flushTimers();
    expect(screen.getByText(/STEP 7\/7/i)).toBeInTheDocument();
  });

  it("shows nodeCount in sequence message", async () => {
    render(<TerminalHarness nodeCount={99} />);
    await flushTimers();
    // The sequence embeds nodeCount in several messages
    const matches = screen.getAllByText(/99/);
    expect(matches.length).toBeGreaterThan(0);
  });

  it("shows success message when all tests pass", async () => {
    render(<TerminalHarness testsTotal={10} testsPassed={10} />);
    await flushTimers();
    // The sequence emits two success messages; either one satisfies the intent.
    const matches = screen.getAllByText(/zero regressions|Remediation complete/i);
    expect(matches.length).toBeGreaterThan(0);
  });

  it("shows failure message when tests fail", async () => {
    render(<TerminalHarness testsTotal={10} testsPassed={8} />);
    await flushTimers();
    // The sequence emits two failure messages; either one satisfies the intent.
    const matches = screen.getAllByText(/FAILED|regression detected/i);
    expect(matches.length).toBeGreaterThan(0);
  });

  it("shows CVE warning when cveCount > 0", async () => {
    render(<TerminalHarness cveCount={3} />);
    await flushTimers();
    expect(screen.getByText(/3 CVE flag\(s\)/i)).toBeInTheDocument();
  });

  it("shows no CVE anti-patterns message when cveCount is 0", async () => {
    render(<TerminalHarness cveCount={0} />);
    await flushTimers();
    expect(
      screen.getByText(/No CVE anti-patterns detected/i)
    ).toBeInTheDocument();
  });

  it("appends Session closed at the end", async () => {
    render(<TerminalHarness />);
    await flushTimers();
    expect(screen.getByText(/Session closed\./i)).toBeInTheDocument();
  });

  it("marks as completed after sequence ends", async () => {
    render(<TerminalHarness testsTotal={5} testsPassed={5} />);
    await flushTimers();
    // Running indicator should be gone
    expect(screen.queryByText(/^Running$/)).not.toBeInTheDocument();
    // Completed badge should appear
    expect(screen.getByText(/✓ Passed/i)).toBeInTheDocument();
  });

  it("shows failed badge when tests failed after completion", async () => {
    render(<TerminalHarness testsTotal={10} testsPassed={8} />);
    await flushTimers();
    expect(screen.getByText(/⚠ 2 failed/i)).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// Rerun behaviour
// ---------------------------------------------------------------------------

describe("TerminalHarness — rerun", () => {
  it("Rerun button is disabled while sequence is running", async () => {
    render(<TerminalHarness />);
    await act(async () => {
      jest.advanceTimersByTime(500);
    });
    const btn = screen.getByRole("button", { name: /rerun/i });
    expect(btn).toBeDisabled();
  });

  it("Rerun button is enabled after sequence completes", async () => {
    render(<TerminalHarness />);
    await flushTimers();
    const btn = screen.getByRole("button", { name: /rerun/i });
    expect(btn).toBeEnabled();
  });

  it("clicking Rerun restarts the sequence", async () => {
    render(<TerminalHarness />);
    await flushTimers();

    const btn = screen.getByRole("button", { name: /rerun/i });
    fireEvent.click(btn);

    // After clicking Rerun, logs are cleared and sequence restarts
    await act(async () => {
      jest.advanceTimersByTime(100);
    });
    expect(screen.getByText(/running/i)).toBeInTheDocument();
  });

  it("clicking Rerun shows engine version message again", async () => {
    render(<TerminalHarness />);
    await flushTimers();

    const btn = screen.getByRole("button", { name: /rerun/i });
    fireEvent.click(btn);
    await flushTimers();

    const versionEntries = screen.getAllByText(
      /GraphWard Autonomous Remediation Engine v1\.0\.0/i
    );
    expect(versionEntries.length).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// Props propagation
// ---------------------------------------------------------------------------

describe("TerminalHarness — props", () => {
  it("renders with all default props without error", () => {
    expect(() => render(<TerminalHarness />)).not.toThrow();
  });

  it("renders with all explicit props without error", () => {
    expect(() =>
      render(
        <TerminalHarness
          nodeCount={100}
          edgeCount={200}
          cveCount={5}
          testsTotal={50}
          testsPassed={45}
        />
      )
    ).not.toThrow();
  });

  it("handles zero values gracefully", async () => {
    render(
      <TerminalHarness
        nodeCount={0}
        edgeCount={0}
        cveCount={0}
        testsTotal={0}
        testsPassed={0}
      />
    );
    await flushTimers();
    // Should complete without errors
    expect(screen.getByText(/Session closed\./i)).toBeInTheDocument();
  });
});
