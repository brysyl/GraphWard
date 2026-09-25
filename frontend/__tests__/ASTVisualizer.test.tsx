/**
 * Tests for ASTVisualizer component.
 *
 * ReactFlow renders canvas elements and has heavy internal state.
 * We mock the entire reactflow module to an element stub so we can
 * test the component's decision logic (empty state, prop wiring, layout)
 * without spinning up a browser canvas.
 */

import React from "react";
import { render, screen } from "@testing-library/react";
import "@testing-library/jest-dom";

// ---------------------------------------------------------------------------
// Mock reactflow — replace all exports with lightweight stubs
// ---------------------------------------------------------------------------

jest.mock("reactflow", () => {
  const React = require("react");

  const ReactFlow = ({
    nodes,
    edges,
    children,
  }: {
    nodes: unknown[];
    edges: unknown[];
    children?: React.ReactNode;
  }) => (
    <div
      data-testid="react-flow"
      data-nodes={nodes.length}
      data-edges={edges.length}
    >
      {children}
    </div>
  );

  const Handle = ({ type, position }: { type: string; position: string }) => (
    <div data-testid={`handle-${type}`} data-position={position} />
  );

  return {
    __esModule: true,
    default: ReactFlow,
    Background: () => <div data-testid="rf-background" />,
    BackgroundVariant: { Dots: "dots" },
    Controls: () => <div data-testid="rf-controls" />,
    MiniMap: () => <div data-testid="rf-minimap" />,
    Handle,
    MarkerType: { ArrowClosed: "arrowclosed" },
    Position: { Top: "top", Bottom: "bottom" },
    addEdge: jest.fn((params, eds) => [...eds, params]),
    useNodesState: (init: unknown[]) => {
      const [nodes, setNodes] = React.useState(init);
      return [nodes, setNodes, jest.fn()];
    },
    useEdgesState: (init: unknown[]) => {
      const [edges, setEdges] = React.useState(init);
      return [edges, setEdges, jest.fn()];
    },
  };
});

import ASTVisualizer from "@/components/ASTVisualizer";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const EMPTY_GRAPH = { nodes: [], links: [] };

const SIMPLE_GRAPH = {
  directed: true,
  nodes: [
    { id: "mod.py::foo", file: "mod.py", line: 1, complexity: 1 },
    { id: "mod.py::bar", file: "mod.py", line: 5, complexity: 3 },
  ],
  links: [{ source: "mod.py::foo", target: "mod.py::bar" }],
};

const COMPLEX_GRAPH = {
  directed: true,
  nodes: [
    { id: "a.py::entry", file: "a.py", line: 1, complexity: 2 },
    { id: "b.py::helper", file: "b.py", line: 10, complexity: 6 },
    { id: "c.py::util", file: "c.py", line: 3, complexity: 9 },
    { id: "d.py::critical", file: "d.py", line: 7, complexity: 12 },
  ],
  links: [
    { source: "a.py::entry", target: "b.py::helper" },
    { source: "b.py::helper", target: "c.py::util" },
    { source: "c.py::util", target: "d.py::critical" },
  ],
};

// ---------------------------------------------------------------------------
// Tests: empty state
// ---------------------------------------------------------------------------

describe("ASTVisualizer — empty state", () => {
  it("renders the empty-state message when no nodes are provided", () => {
    render(<ASTVisualizer callGraphJson={EMPTY_GRAPH} />);
    expect(
      screen.getByText(/no graph data/i)
    ).toBeInTheDocument();
  });

  it("does not render the ReactFlow canvas in empty state", () => {
    render(<ASTVisualizer callGraphJson={EMPTY_GRAPH} />);
    expect(screen.queryByTestId("react-flow")).not.toBeInTheDocument();
  });

  it("handles completely missing nodes/links keys gracefully", () => {
    render(<ASTVisualizer callGraphJson={{}} />);
    expect(screen.getByText(/no graph data/i)).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// Tests: graph rendering
// ---------------------------------------------------------------------------

describe("ASTVisualizer — graph rendering", () => {
  it("renders ReactFlow when nodes are present", () => {
    render(<ASTVisualizer callGraphJson={SIMPLE_GRAPH} />);
    expect(screen.getByTestId("react-flow")).toBeInTheDocument();
  });

  it("passes correct node count to ReactFlow", () => {
    render(<ASTVisualizer callGraphJson={SIMPLE_GRAPH} />);
    const rf = screen.getByTestId("react-flow");
    expect(rf).toHaveAttribute("data-nodes", "2");
  });

  it("passes correct edge count to ReactFlow", () => {
    render(<ASTVisualizer callGraphJson={SIMPLE_GRAPH} />);
    const rf = screen.getByTestId("react-flow");
    expect(rf).toHaveAttribute("data-edges", "1");
  });

  it("renders Background, Controls, and MiniMap inside ReactFlow", () => {
    render(<ASTVisualizer callGraphJson={SIMPLE_GRAPH} />);
    expect(screen.getByTestId("rf-background")).toBeInTheDocument();
    expect(screen.getByTestId("rf-controls")).toBeInTheDocument();
    expect(screen.getByTestId("rf-minimap")).toBeInTheDocument();
  });

  it("passes all nodes from complex graph to ReactFlow", () => {
    render(<ASTVisualizer callGraphJson={COMPLEX_GRAPH} />);
    const rf = screen.getByTestId("react-flow");
    expect(rf).toHaveAttribute("data-nodes", "4");
  });

  it("passes all edges from complex graph to ReactFlow", () => {
    render(<ASTVisualizer callGraphJson={COMPLEX_GRAPH} />);
    const rf = screen.getByTestId("react-flow");
    expect(rf).toHaveAttribute("data-edges", "3");
  });
});

// ---------------------------------------------------------------------------
// Tests: computeLayout (exported indirectly via render behaviour)
// ---------------------------------------------------------------------------

describe("ASTVisualizer — layout computation", () => {
  it("single isolated node renders without crashing", () => {
    const graph = {
      nodes: [{ id: "solo.py::fn", file: "solo.py", line: 1, complexity: 1 }],
      links: [],
    };
    render(<ASTVisualizer callGraphJson={graph} />);
    expect(screen.getByTestId("react-flow")).toHaveAttribute("data-nodes", "1");
  });

  it("graph with no links still renders all nodes", () => {
    const graph = {
      nodes: [
        { id: "a.py::x", file: "a.py", line: 1, complexity: 1 },
        { id: "b.py::y", file: "b.py", line: 2, complexity: 1 },
      ],
      links: [],
    };
    render(<ASTVisualizer callGraphJson={graph} />);
    expect(screen.getByTestId("react-flow")).toHaveAttribute("data-nodes", "2");
  });

  it("re-renders correctly when callGraphJson prop changes", () => {
    const { rerender } = render(<ASTVisualizer callGraphJson={SIMPLE_GRAPH} />);
    expect(screen.getByTestId("react-flow")).toHaveAttribute("data-nodes", "2");

    rerender(<ASTVisualizer callGraphJson={COMPLEX_GRAPH} />);
    expect(screen.getByTestId("react-flow")).toHaveAttribute("data-nodes", "4");
  });

  it("transitions from graph to empty state when nodes removed", () => {
    const { rerender } = render(<ASTVisualizer callGraphJson={SIMPLE_GRAPH} />);
    expect(screen.getByTestId("react-flow")).toBeInTheDocument();

    rerender(<ASTVisualizer callGraphJson={EMPTY_GRAPH} />);
    expect(screen.queryByTestId("react-flow")).not.toBeInTheDocument();
    expect(screen.getByText(/no graph data/i)).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// Tests: node data defaults
// ---------------------------------------------------------------------------

describe("ASTVisualizer — node data defaults", () => {
  it("handles node with missing file gracefully", () => {
    const graph = {
      nodes: [{ id: "x.py::fn" }],
      links: [],
    };
    // Should not throw
    expect(() =>
      render(<ASTVisualizer callGraphJson={graph} />)
    ).not.toThrow();
  });

  it("handles node with missing complexity gracefully", () => {
    const graph = {
      nodes: [{ id: "x.py::fn", file: "x.py", line: 1 }],
      links: [],
    };
    expect(() =>
      render(<ASTVisualizer callGraphJson={graph} />)
    ).not.toThrow();
  });
});
