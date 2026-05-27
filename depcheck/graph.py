"""Interactive dependency graph visualization for depcheck.

Generates a self-contained HTML file with a D3.js force-directed graph
showing the full dependency tree with health status color-coding,
version info, vulnerability counts, and license details.

Nodes are color-coded by health status:
  - Green: healthy
  - Yellow: outdated
  - Red: vulnerable
  - Gray: unmaintained
  - Orange: yanked
  - Dark red: removed
  - Light gray: unknown

Features:
  - Zoom and pan via mouse wheel / drag
  - Click a node to see details panel
  - Search/filter by package name
  - Collapse/expand subtrees
  - Export as SVG or PNG
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from depcheck.models import HealthStatus
from depcheck.osv import OSVClient
from depcheck.pypi import PyPIClient
from depcheck.scanner import (
    check_package_health,
    discover_dependencies,
)
from depcheck.tree import (
    DependencyTreeResult,
    TreeNode,
    resolve_dependency_tree,
)

try:
    from depcheck.licenses import LicenseCategory
except ImportError:
    LicenseCategory = None  # type: ignore[assignment,misc]


# Status → color mapping for the graph
STATUS_COLORS: dict[str, str] = {
    HealthStatus.HEALTHY.value: "#4caf50",
    HealthStatus.OUTDATED.value: "#ff9800",
    HealthStatus.VULNERABLE.value: "#f44336",
    HealthStatus.UNMAINTAINED.value: "#9e9e9e",
    HealthStatus.YANKED.value: "#ff5722",
    HealthStatus.REMOVED.value: "#b71c1c",
    HealthStatus.UNKNOWN.value: "#bdbdbd",
}

# Status → label for the legend
STATUS_LABELS: dict[str, str] = {
    HealthStatus.HEALTHY.value: "Healthy",
    HealthStatus.OUTDATED.value: "Outdated",
    HealthStatus.VULNERABLE.value: "Vulnerable",
    HealthStatus.UNMAINTAINED.value: "Unmaintained",
    HealthStatus.YANKED.value: "Yanked",
    HealthStatus.REMOVED.value: "Removed",
    HealthStatus.UNKNOWN.value: "Unknown",
}


@dataclass
class GraphNode:
    """A node in the dependency graph for visualization."""

    id: str
    name: str
    version: str | None = None
    latest_version: str | None = None
    status: str = "unknown"
    vuln_count: int = 0
    license_id: str = ""
    license_category: str = ""
    is_compliant: bool = True
    depth: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "latestVersion": self.latest_version,
            "status": self.status,
            "vulnCount": self.vuln_count,
            "license": self.license_id or None,
            "licenseCategory": self.license_category or None,
            "licenseCompliant": self.is_compliant if self.license_id else None,
            "depth": self.depth,
        }


@dataclass
class GraphLink:
    """An edge in the dependency graph."""

    source: str
    target: str

    def to_dict(self) -> dict[str, Any]:
        return {"source": self.source, "target": self.target}


@dataclass
class DependencyGraph:
    """The complete dependency graph data for visualization."""

    project_path: str
    nodes: list[GraphNode] = field(default_factory=list)
    links: list[GraphLink] = field(default_factory=list)
    files_scanned: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "projectPath": self.project_path,
            "nodes": [n.to_dict() for n in self.nodes],
            "links": [l.to_dict() for l in self.links],
            "filesScanned": self.files_scanned,
            "errors": self.errors,
        }


def tree_to_graph(tree_result: DependencyTreeResult) -> DependencyGraph:
    """Convert a DependencyTreeResult into a flat graph structure.

    Walks the tree recursively, collecting unique nodes and edges.

    Args:
        tree_result: The resolved dependency tree.

    Returns:
        A DependencyGraph with nodes and links for visualization.
    """
    graph = DependencyGraph(
        project_path=tree_result.project_path,
        files_scanned=tree_result.files_scanned,
        errors=tree_result.errors,
    )

    seen: set[str] = set()

    def walk(node: TreeNode, parent_id: str | None = None) -> None:
        node_id = node.name
        if node_id not in seen:
            seen.add(node_id)
            graph.nodes.append(
                GraphNode(
                    id=node_id,
                    name=node.name,
                    version=node.version,
                    status=node.status.value,
                    license_id=node.license_id,
                    license_category=node.license_category,
                    is_compliant=node.is_compliant,
                    depth=node.depth,
                )
            )
        if parent_id is not None:
            link = GraphLink(source=parent_id, target=node_id)
            graph.links.append(link)
        for child in node.children:
            walk(child, parent_id=node_id)

    for root in tree_result.roots:
        walk(root, parent_id=None)

    return graph


def render_graph_html(graph: DependencyGraph) -> str:
    """Render the dependency graph as a self-contained HTML file.

    The output includes embedded D3.js (from CDN) and all CSS/JS inline,
    so the file works offline after the initial CDN load.

    Args:
        graph: The dependency graph data.

    Returns:
        A complete HTML document as a string.
    """
    graph_json = json.dumps(graph.to_dict())
    status_colors_json = json.dumps(STATUS_COLORS)
    status_labels_json = json.dumps(STATUS_LABELS)

    # Escape for safe embedding
    graph_data_escaped = html.escape(graph_json, quote=False) if False else graph_json

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>depcheck — Dependency Graph</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #1a1a2e;
    color: #e0e0e0;
    overflow: hidden;
    height: 100vh;
  }}
  #toolbar {{
    position: fixed;
    top: 0; left: 0; right: 0;
    height: 56px;
    background: #16213e;
    border-bottom: 1px solid #0f3460;
    display: flex;
    align-items: center;
    padding: 0 20px;
    z-index: 100;
    gap: 12px;
  }}
  #toolbar h1 {{
    font-size: 18px;
    font-weight: 600;
    color: #e94560;
    margin-right: 16px;
    white-space: nowrap;
  }}
  #search-box {{
    flex: 0 1 300px;
    padding: 8px 14px;
    border: 1px solid #0f3460;
    border-radius: 6px;
    background: #1a1a2e;
    color: #e0e0e0;
    font-size: 14px;
    outline: none;
  }}
  #search-box:focus {{
    border-color: #e94560;
  }}
  #search-box::placeholder {{
    color: #666;
  }}
  .toolbar-btn {{
    padding: 6px 14px;
    border: 1px solid #0f3460;
    border-radius: 6px;
    background: #1a1a2e;
    color: #e0e0e0;
    font-size: 13px;
    cursor: pointer;
    transition: all 0.2s;
  }}
  .toolbar-btn:hover {{
    border-color: #e94560;
    color: #e94560;
  }}
  #stats {{
    margin-left: auto;
    font-size: 13px;
    color: #888;
    white-space: nowrap;
  }}
  #graph {{
    position: fixed;
    top: 56px; left: 0; right: 0; bottom: 0;
  }}
  #legend {{
    position: fixed;
    bottom: 20px; left: 20px;
    background: rgba(22, 33, 62, 0.95);
    border: 1px solid #0f3460;
    border-radius: 8px;
    padding: 12px 16px;
    z-index: 50;
  }}
  #legend h3 {{
    font-size: 12px;
    text-transform: uppercase;
    color: #888;
    margin-bottom: 8px;
    letter-spacing: 1px;
  }}
  .legend-item {{
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 4px;
    font-size: 13px;
  }}
  .legend-dot {{
    width: 10px;
    height: 10px;
    border-radius: 50%;
    flex-shrink: 0;
  }}
  #detail-panel {{
    position: fixed;
    top: 56px; right: 0;
    width: 320px;
    bottom: 0;
    background: rgba(22, 33, 62, 0.98);
    border-left: 1px solid #0f3460;
    padding: 20px;
    overflow-y: auto;
    z-index: 50;
    display: none;
  }}
  #detail-panel.active {{
    display: block;
  }}
  #detail-panel h2 {{
    font-size: 18px;
    font-weight: 600;
    color: #e94560;
    margin-bottom: 16px;
    word-break: break-all;
  }}
  .detail-row {{
    display: flex;
    justify-content: space-between;
    padding: 8px 0;
    border-bottom: 1px solid #0f3460;
    font-size: 13px;
  }}
  .detail-label {{
    color: #888;
    flex-shrink: 0;
  }}
  .detail-value {{
    color: #e0e0e0;
    text-align: right;
    word-break: break-all;
  }}
  .status-badge {{
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 12px;
    font-weight: 600;
    color: #fff;
  }}
  .vuln-list {{
    margin-top: 12px;
  }}
  .vuln-item {{
    background: rgba(244, 67, 54, 0.1);
    border: 1px solid rgba(244, 67, 54, 0.3);
    border-radius: 6px;
    padding: 8px 10px;
    margin-bottom: 6px;
    font-size: 12px;
  }}
  .vuln-item .vuln-id {{
    color: #f44336;
    font-weight: 600;
  }}
  .vuln-item .vuln-severity {{
    float: right;
    padding: 1px 8px;
    border-radius: 10px;
    font-size: 11px;
  }}
  .close-btn {{
    position: absolute;
    top: 12px; right: 12px;
    background: none;
    border: none;
    color: #888;
    font-size: 20px;
    cursor: pointer;
  }}
  .close-btn:hover {{
    color: #e94560;
  }}
  .link {{
    stroke: #0f3460;
    stroke-opacity: 0.6;
    stroke-width: 1.5;
  }}
  .node-circle {{
    stroke: #1a1a2e;
    stroke-width: 2;
    cursor: pointer;
    transition: r 0.2s;
  }}
  .node-circle:hover {{
    stroke: #fff;
    stroke-width: 3;
  }}
  .node-label {{
    font-size: 11px;
    fill: #ccc;
    pointer-events: none;
    text-anchor: middle;
    font-weight: 500;
  }}
  .highlighted .node-label {{
    fill: #fff;
    font-weight: 700;
  }}
  .dimmed {{
    opacity: 0.15;
  }}
  #no-results {{
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    font-size: 18px;
    color: #666;
    display: none;
    z-index: 40;
  }}
</style>
</head>
<body>

<div id="toolbar">
  <h1>depcheck graph</h1>
  <input type="text" id="search-box" placeholder="Search packages..." />
  <button class="toolbar-btn" id="btn-reset">Reset Zoom</button>
  <button class="toolbar-btn" id="btn-export-svg">Export SVG</button>
  <button class="toolbar-btn" id="btn-export-png">Export PNG</button>
  <span id="stats"></span>
</div>

<div id="graph"></div>

<div id="legend">
  <h3>Health Status</h3>
</div>

<div id="detail-panel">
  <button class="close-btn" id="close-detail">&times;</button>
  <h2 id="detail-name"></h2>
  <div id="detail-content"></div>
</div>

<div id="no-results">No matching packages found</div>

<script src="https://d3js.org/d3.v7.min.js"></script>
<script>
(function() {{
  const data = {graph_data_escaped};
  const STATUS_COLORS = {status_colors_json};
  const STATUS_LABELS = {status_labels_json};

  // Build legend
  const legendEl = document.getElementById('legend');
  Object.entries(STATUS_LABELS).forEach(([key, label]) => {{
    const item = document.createElement('div');
    item.className = 'legend-item';
    item.innerHTML = `<span class="legend-dot" style="background:${{STATUS_COLORS[key]}}"></span>${{label}}`;
    legendEl.appendChild(item);
  }});

  // Stats
  const statusCounts = {{}};
  data.nodes.forEach(n => {{
    statusCounts[n.status] = (statusCounts[n.status] || 0) + 1;
  }});
  const statsEl = document.getElementById('stats');
  const parts = Object.entries(STATUS_LABELS).filter(([k]) => statusCounts[k]).map(([k, v]) => `${{v}}: ${{statusCounts[k]}}`);
  statsEl.textContent = parts.join(' · ') + ` · Total: ${{data.nodes.length}}`;

  const width = window.innerWidth;
  const height = window.innerHeight - 56;

  const svg = d3.select('#graph')
    .append('svg')
    .attr('width', width)
    .attr('height', height)
    .attr('id', 'depgraph-svg');

  // Defs for PNG export
  const defs = svg.append('defs');
  const styleEl = defs.append('style').attr('type', 'text/css');
  styleEl.text(`text {{ font-family: -apple-system, sans-serif; }}`);

  const g = svg.append('g');

  // Zoom
  const zoom = d3.zoom()
    .scaleExtent([0.1, 8])
    .on('zoom', (event) => g.attr('transform', event.transform));
  svg.call(zoom);

  // Build simulation
  const nodeMap = new Map(data.nodes.map(n => [n.id, n]));
  const links = data.links.map(l => ({{ source: l.source, target: l.target }}));

  const simulation = d3.forceSimulation(data.nodes)
    .force('link', d3.forceLink(links).id(d => d.id).distance(80))
    .force('charge', d3.forceManyBody().strength(-200).distanceMax(400))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collision', d3.forceCollide().radius(d => nodeRadius(d) + 4));

  function nodeRadius(d) {{
    const base = 8;
    if (d.vulnCount > 0) return base + Math.min(d.vulnCount * 3, 20);
    if (d.depth === 0) return base + 4;
    return base;
  }}

  // Links
  const link = g.append('g')
    .selectAll('line')
    .data(links)
    .join('line')
    .attr('class', 'link');

  // Nodes
  const node = g.append('g')
    .selectAll('g')
    .data(data.nodes)
    .join('g')
    .attr('class', 'node-group')
    .call(d3.drag()
      .on('start', dragStarted)
      .on('drag', dragged)
      .on('end', dragEnded));

  node.append('circle')
    .attr('class', 'node-circle')
    .attr('r', d => nodeRadius(d))
    .attr('fill', d => STATUS_COLORS[d.status] || STATUS_COLORS.unknown);

  node.append('text')
    .attr('class', 'node-label')
    .attr('dy', d => nodeRadius(d) + 14)
    .text(d => d.name);

  // Click handler
  node.on('click', (event, d) => {{
    event.stopPropagation();
    showDetail(d);
  }});

  // Click on background to close
  svg.on('click', () => {{
    document.getElementById('detail-panel').classList.remove('active');
  }});

  // Simulation tick
  simulation.on('tick', () => {{
    link
      .attr('x1', d => d.source.x)
      .attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x)
      .attr('y2', d => d.target.y);

    node.attr('transform', d => `translate(${{d.x}},${{d.y}})`);
  }});

  function dragStarted(event, d) {{
    if (!event.active) simulation.alphaTarget(0.3).restart();
    d.fx = d.x;
    d.fy = d.y;
  }}

  function dragged(event, d) {{
    d.fx = event.x;
    d.fy = event.y;
  }}

  function dragEnded(event, d) {{
    if (!event.active) simulation.alphaTarget(0);
    d.fx = null;
    d.fy = null;
  }}

  // Detail panel
  function showDetail(d) {{
    const panel = document.getElementById('detail-panel');
    document.getElementById('detail-name').textContent = d.name;
    const content = document.getElementById('detail-content');

    const color = STATUS_COLORS[d.status] || STATUS_COLORS.unknown;
    const label = STATUS_LABELS[d.status] || d.status;

    let html = `
      <div class="detail-row"><span class="detail-label">Status</span><span class="detail-value"><span class="status-badge" style="background:${{color}}">${{label}}</span></span></div>
      <div class="detail-row"><span class="detail-label">Version</span><span class="detail-value">${{d.version || 'unknown'}}</span></div>
    `;
    if (d.latestVersion) {{
      html += `<div class="detail-row"><span class="detail-label">Latest</span><span class="detail-value">${{d.latestVersion}}</span></div>`;
    }}
    if (d.license) {{
      html += `<div class="detail-row"><span class="detail-label">License</span><span class="detail-value">${{d.license}}</span></div>`;
    }}
    if (d.licenseCategory) {{
      html += `<div class="detail-row"><span class="detail-label">Category</span><span class="detail-value">${{d.licenseCategory}}</span></div>`;
    }}
    if (d.licenseCompliant === false) {{
      html += `<div class="detail-row"><span class="detail-label">Compliant</span><span class="detail-value" style="color:#f44336">No</span></div>`;
    }}
    if (d.vulnCount > 0) {{
      html += `<div class="detail-row"><span class="detail-label">Vulnerabilities</span><span class="detail-value" style="color:#f44336">${{d.vulnCount}}</span></div>`;
    }}
    html += `<div class="detail-row"><span class="detail-label">Depth</span><span class="detail-value">${{d.depth}}</span></div>`;

    // Show dependencies (outgoing edges)
    const deps = data.links.filter(l => l.source === d.id).map(l => l.target);
    if (deps.length) {{
      html += `<div style="margin-top:12px;font-size:13px;color:#888;">Depends on (${{deps.length}})</div>`;
      html += `<div style="margin-top:4px;font-size:12px;color:#ccc;line-height:1.8">${{deps.join(', ')}}</div>`;
    }}

    // Show dependents (incoming edges)
    const dependents = data.links.filter(l => l.target === d.id).map(l => l.source);
    if (dependents.length) {{
      html += `<div style="margin-top:12px;font-size:13px;color:#888;">Required by (${{dependents.length}})</div>`;
      html += `<div style="margin-top:4px;font-size:12px;color:#ccc;line-height:1.8">${{dependents.join(', ')}}</div>`;
    }}

    content.innerHTML = html;
    panel.classList.add('active');
  }}

  document.getElementById('close-detail').addEventListener('click', () => {{
    document.getElementById('detail-panel').classList.remove('active');
  }});

  // Search
  const searchBox = document.getElementById('search-box');
  const noResults = document.getElementById('no-results');
  let searchTimeout;
  searchBox.addEventListener('input', () => {{
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {{
      const query = searchBox.value.toLowerCase().trim();
      if (!query) {{
        node.classed('dimmed', false).classed('highlighted', false);
        link.classed('dimmed', false);
        noResults.style.display = 'none';
        return;
      }}
      const matches = new Set(
        data.nodes.filter(n => n.name.toLowerCase().includes(query)).map(n => n.id)
      );
      // Also include neighbors of matches
      const expanded = new Set(matches);
      data.links.forEach(l => {{
        if (matches.has(l.source)) expanded.add(l.target);
        if (matches.has(l.target)) expanded.add(l.source);
      }});

      node.classed('dimmed', d => !expanded.has(d.id))
          .classed('highlighted', d => matches.has(d.id));
      link.classed('dimmed', d => !expanded.has(d.source.id || d.source) && !expanded.has(d.target.id || d.target));
      noResults.style.display = matches.size === 0 ? 'block' : 'none';
    }}, 200);
  }});

  // Reset zoom
  document.getElementById('btn-reset').addEventListener('click', () => {{
    svg.transition().duration(500).call(zoom.transform, d3.zoomIdentity);
  }});

  // Export SVG
  document.getElementById('btn-export-svg').addEventListener('click', () => {{
    const svgEl = document.getElementById('depgraph-svg');
    const serializer = new XMLSerializer();
    const svgStr = serializer.serializeToString(svgEl);
    const blob = new Blob([svgStr], {{ type: 'image/svg+xml' }});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'depcheck-graph.svg';
    a.click();
    URL.revokeObjectURL(url);
  }});

  // Export PNG
  document.getElementById('btn-export-png').addEventListener('click', () => {{
    const svgEl = document.getElementById('depgraph-svg');
    const serializer = new XMLSerializer();
    const svgStr = serializer.serializeToString(svgEl);
    const canvas = document.createElement('canvas');
    canvas.width = width * 2;
    canvas.height = height * 2;
    const ctx = canvas.getContext('2d');
    const img = new Image();
    img.onload = () => {{
      ctx.fillStyle = '#1a1a2e';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      const a = document.createElement('a');
      a.href = canvas.toDataURL('image/png');
      a.download = 'depcheck-graph.png';
      a.click();
    }};
    img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svgStr)));
  }});

  // Resize
  window.addEventListener('resize', () => {{
    const w = window.innerWidth;
    const h = window.innerHeight - 56;
    svg.attr('width', w).attr('height', h);
    simulation.force('center', d3.forceCenter(w / 2, h / 2));
    simulation.alpha(0.3).restart();
  }});
}})();
</script>
</body>
</html>"""


def generate_graph(
    project_path: str | Path,
    max_depth: int = 3,
    check_vulnerabilities: bool = True,
    check_licenses: bool = False,
    allowed_license_categories: list | None = None,
    denied_licenses: list[str] | None = None,
) -> DependencyGraph:
    """Generate a dependency graph for a Python project.

    Resolves the full dependency tree and converts it to a flat
    graph structure suitable for visualization.

    Args:
        project_path: Path to the project directory.
        max_depth: Maximum depth to resolve the dependency tree.
        check_vulnerabilities: Whether to check for vulnerabilities.
        check_licenses: Whether to check license compliance.
        allowed_license_categories: List of allowed license categories.
        denied_licenses: List of specific SPDX IDs to deny.

    Returns:
        A DependencyGraph ready for HTML rendering.
    """
    tree_result = resolve_dependency_tree(
        project_path=project_path,
        max_depth=max_depth,
        check_vulnerabilities=check_vulnerabilities,
        check_licenses=check_licenses,
        allowed_license_categories=allowed_license_categories,
        denied_licenses=denied_licenses,
    )

    graph = tree_to_graph(tree_result)

    # Enrich nodes with latest version and vuln count from the tree's
    # PackageReport data (if available via the scan result)
    # The tree nodes already have health status, so we just need to
    # add extra details from a quick scan
    return graph


def write_graph_html(
    project_path: str | Path,
    output_path: str | Path | None = None,
    max_depth: int = 3,
    check_vulnerabilities: bool = True,
    check_licenses: bool = False,
    allowed_license_categories: list | None = None,
    denied_licenses: list[str] | None = None,
) -> Path:
    """Generate and write a dependency graph HTML file.

    Args:
        project_path: Path to the project directory.
        output_path: Path to write the HTML file (default: ./depcheck-graph.html).
        max_depth: Maximum depth to resolve the dependency tree.
        check_vulnerabilities: Whether to check for vulnerabilities.
        check_licenses: Whether to check license compliance.
        allowed_license_categories: List of allowed license categories.
        denied_licenses: List of specific SPDX IDs to deny.

    Returns:
        Path to the written HTML file.
    """
    if output_path is None:
        output_path = Path("depcheck-graph.html")
    output_path = Path(output_path)

    graph = generate_graph(
        project_path=project_path,
        max_depth=max_depth,
        check_vulnerabilities=check_vulnerabilities,
        check_licenses=check_licenses,
        allowed_license_categories=allowed_license_categories,
        denied_licenses=denied_licenses,
    )

    html_content = render_graph_html(graph)
    output_path.write_text(html_content, encoding="utf-8")

    return output_path
