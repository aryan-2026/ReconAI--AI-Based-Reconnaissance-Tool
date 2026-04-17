"""
ReconAI - Attack Surface Graph Generator
Interactive visual map of the full attack surface using pyvis.
Fallback: pure-JS D3 HTML if pyvis unavailable.
"""
import json
from pathlib import Path
from typing import Dict
from utils.logger import section, success, warn


class AttackSurfaceGraph:

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir

    def generate(self, target: str, recon_data: dict) -> str:
        section("Attack Surface Graph Generator")
        try:
            from pyvis.network import Network
            return self._generate_pyvis(target, recon_data)
        except ImportError:
            warn("pyvis not installed — generating fallback HTML graph")
            return self._generate_d3_html(target, recon_data)

    # ─────────────────────────────────────────────────────────
    # pyvis graph (primary)
    # ─────────────────────────────────────────────────────────

    def _generate_pyvis(self, target: str, recon_data: dict) -> str:
        from pyvis.network import Network

        net = Network(
            height="920px", width="100%",
            bgcolor="#0d1117", font_color="#c9d1d9",
            directed=True
        )
        net.set_options("""
        {
          "nodes": {"borderWidth": 2, "shadow": true},
          "edges": {"smooth": {"type": "curvedCW", "roundness": 0.2}, "arrows": {"to": {"enabled": true, "scaleFactor": 0.5}}},
          "physics": {
            "barnesHut": {"gravitationalConstant": -8000, "springLength": 130},
            "minVelocity": 0.75
          }
        }
        """)

        # Track added node IDs so we can conditionally add edges
        added = set()

        def add_node(node_id, **kwargs):
            if node_id not in added:
                net.add_node(node_id, **kwargs)
                added.add(node_id)

        def add_edge(src, dst, **kwargs):
            if src in added and dst in added:
                try:
                    net.add_edge(src, dst, **kwargs)
                except Exception:
                    pass

        # Root
        add_node(target, label=target, color="#f78166", size=30,
                 title=f"Root Target: {target}", shape="star")

        # Live hosts → build lookup
        live_url_set = set()
        for h in recon_data.get("live_hosts", []):
            if isinstance(h, dict):
                live_url_set.add(h.get("url", "").split("//")[-1].split("/")[0])
            elif isinstance(h, str):
                live_url_set.add(h.split("//")[-1].split("/")[0])

        # Subdomains
        for sub in recon_data.get("subdomains", [])[:120]:
            is_live = sub in live_url_set
            color   = "#3fb950" if is_live else "#6e7681"
            size    = 13 if is_live else 8
            add_node(sub, label=sub, color=color, size=size,
                     title=f"Subdomain: {sub}\nStatus: {'LIVE' if is_live else 'DEAD'}")
            add_edge(target, sub, color="#30363d")

        # Live hosts with detail
        for host in recon_data.get("live_hosts", [])[:60]:
            if isinstance(host, dict):
                url      = host.get("url", "")
                title_h  = host.get("title", "")
                techs    = ", ".join(host.get("technologies", [])[:4])
                category = host.get("category", "unknown")
                priority = host.get("priority_score", 3)
                if not url:
                    continue
                color  = self._priority_color(priority)
                domain = url.split("//")[-1].split("/")[0]
                tooltip = f"URL: {url}\nTitle: {title_h}\nTech: {techs}\nCategory: {category}\nPriority: {priority}/10"
                add_node(url, label=url[:45], color=color,
                         size=10 + priority, title=tooltip, shape="dot")
                # Connect URL to its subdomain node if it exists
                if domain in added:
                    add_edge(domain, url, color="#58a6ff")
                else:
                    add_edge(target, url, color="#58a6ff")

        # Vuln hints
        for hint in recon_data.get("vulnerability_hints", [])[:35]:
            if hint.get("priority") in ("CRITICAL", "HIGH"):
                hint_id   = f"HINT:{hint['hint_type']}:{hint.get('target','')[:30]}"
                hint_label = hint["hint_type"]
                add_node(hint_id, label=hint_label, color="#ff7b72",
                         size=14, shape="diamond", title=hint.get("reason", ""))
                t_url = hint.get("target", "")
                if t_url and t_url in added:
                    add_edge(t_url, hint_id, color="#ff7b72", dashes=True)
                elif target in added:
                    add_edge(target, hint_id, color="#ff7b72", dashes=True)

        # Cloud assets
        for asset in recon_data.get("cloud_assets", [])[:30]:
            url    = asset.get("url", "")
            status = asset.get("status", "")
            if not url:
                continue
            color = "#ff7b72" if "PUBLIC" in status else "#e3b341"
            add_node(url, label=url[:40], color=color, size=12,
                     shape="triangleDown",
                     title=f"Cloud: {asset.get('provider','')}\nStatus: {status}")
            add_edge(target, url, color=color)

        # Open ports
        for host_h, ports in (recon_data.get("open_ports") or {}).items():
            if host_h not in added:
                add_node(host_h, label=host_h, color="#8b949e", size=10, shape="dot",
                         title=f"Host: {host_h}")
                add_edge(target, host_h, color="#30363d")
            for p in ports[:6]:
                port_id = f"{host_h}:{p['port']}"
                add_node(port_id, label=f":{p['port']}/{p['service']}",
                         color="#e3b341" if p.get("interesting") else "#30363d",
                         size=8, shape="box",
                         title=f"Port {p['port']} - {p.get('service','')} {p.get('version','')}")
                add_edge(host_h, port_id, color="#30363d")

        output_path = self.output_dir / "attack_surface_graph.html"
        net.save_graph(str(output_path))
        self._inject_legend(output_path)
        success(f"Attack surface graph → {output_path}")
        return str(output_path)

    # ─────────────────────────────────────────────────────────
    # D3 fallback (no pyvis)
    # ─────────────────────────────────────────────────────────

    def _generate_d3_html(self, target: str, recon_data: dict) -> str:
        nodes, links = [], []
        nids = {}

        def node(nid, label, group, size=10, tooltip=""):
            if nid not in nids:
                idx = len(nodes)
                nids[nid] = idx
                nodes.append({"id": idx, "label": label, "group": group,
                               "size": size, "tooltip": tooltip})
            return nids[nid]

        def link(src, dst, color="#555"):
            if src in nids and dst in nids:
                links.append({"source": nids[src], "target": nids[dst], "color": color})

        node(target, target, "root", 20, f"Root: {target}")
        for sub in recon_data.get("subdomains", [])[:80]:
            node(sub, sub, "subdomain", 8, f"Subdomain: {sub}")
            link(target, sub)
        for h in recon_data.get("live_hosts", [])[:40]:
            if isinstance(h, dict):
                url = h.get("url", "")
                if url:
                    node(url, url[:35], "live", 12, f"{url}\n{h.get('title','')}")
                    domain = url.split("//")[-1].split("/")[0]
                    link(domain if domain in nids else target, url, "#58a6ff")

        graph_data = json.dumps({"nodes": nodes, "links": links})

        html = f"""<!DOCTYPE html><html>
<head><meta charset="utf-8"><title>ReconAI - {target}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js"></script>
<style>
body{{margin:0;background:#0d1117;color:#c9d1d9;font-family:monospace;}}
svg{{width:100vw;height:100vh;}}
.tooltip{{position:absolute;background:#161b22;border:1px solid #30363d;padding:8px;border-radius:4px;font-size:11px;pointer-events:none;}}
text{{font-size:10px;fill:#c9d1d9;}}
</style></head>
<body>
<div style="position:fixed;top:10px;left:10px;background:#161b22;border:1px solid #30363d;padding:12px;border-radius:8px;z-index:10;">
  <b style="color:#f78166">⬡ ReconAI — {target}</b><br>
  <span style="color:#3fb950">●</span> Live &nbsp;
  <span style="color:#6e7681">●</span> Dead &nbsp;
  <span style="color:#58a6ff">●</span> Host
</div>
<svg id="graph"></svg>
<div class="tooltip" id="tip" style="display:none;"></div>
<script>
const data = {graph_data};
const colorMap = {{root:"#f78166",subdomain:"#6e7681",live:"#3fb950",hint:"#ff7b72"}};
const svg = d3.select("#graph");
const width = window.innerWidth, height = window.innerHeight;
const sim = d3.forceSimulation(data.nodes)
  .force("link", d3.forceLink(data.links).id(d=>d.id).distance(80))
  .force("charge", d3.forceManyBody().strength(-200))
  .force("center", d3.forceCenter(width/2, height/2));
const link = svg.append("g").selectAll("line").data(data.links).enter().append("line")
  .attr("stroke", d=>d.color||"#30363d").attr("stroke-width", 1);
const node = svg.append("g").selectAll("circle").data(data.nodes).enter().append("circle")
  .attr("r", d=>d.size||8).attr("fill", d=>colorMap[d.group]||"#8b949e")
  .call(d3.drag().on("start", (e,d)=>{{if(!e.active)sim.alphaTarget(0.3).restart();d.fx=d.x;d.fy=d.y;}})
    .on("drag", (e,d)=>{{d.fx=e.x;d.fy=e.y;}})
    .on("end", (e,d)=>{{if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null;}})
  ).on("mouseover",(e,d)=>{{
    const t=document.getElementById("tip");
    t.style.display="block";t.style.left=e.pageX+10+"px";t.style.top=e.pageY-20+"px";
    t.textContent=d.tooltip||d.label;
  }}).on("mouseout",()=>document.getElementById("tip").style.display="none");
sim.on("tick",()=>{{
  link.attr("x1",d=>d.source.x).attr("y1",d=>d.source.y)
      .attr("x2",d=>d.target.x).attr("y2",d=>d.target.y);
  node.attr("cx",d=>d.x).attr("cy",d=>d.y);
}});
</script></body></html>"""

        output_path = self.output_dir / "attack_surface_graph.html"
        output_path.write_text(html)
        success(f"D3 graph saved → {output_path}")
        return str(output_path)

    # ─────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────

    def _priority_color(self, score: int) -> str:
        if score >= 9: return "#ff7b72"
        if score >= 7: return "#e3b341"
        if score >= 5: return "#58a6ff"
        return "#3fb950"

    def _inject_legend(self, html_path: Path):
        legend = """
<div style="position:fixed;top:10px;left:10px;background:#161b22;border:1px solid #30363d;
            border-radius:8px;padding:12px;z-index:999;color:#c9d1d9;font-family:monospace;font-size:12px;">
  <div style="font-weight:bold;margin-bottom:8px;color:#f78166;">⬡ ReconAI Attack Surface</div>
  <div><span style="color:#f78166">★</span> Root Target</div>
  <div><span style="color:#3fb950">●</span> Live Subdomain</div>
  <div><span style="color:#6e7681">●</span> Dead Subdomain</div>
  <div><span style="color:#ff7b72">●</span> Critical Priority</div>
  <div><span style="color:#e3b341">●</span> High Priority</div>
  <div><span style="color:#58a6ff">●</span> Medium Priority</div>
  <div><span style="color:#ff7b72">◆</span> Vuln Hint (CRITICAL/HIGH)</div>
  <div><span style="color:#e3b341">▼</span> Cloud Asset</div>
  <div><span style="color:#e3b341">▪</span> Open Port</div>
</div>"""
        content = html_path.read_text()
        html_path.write_text(content.replace("</body>", legend + "\n</body>"))
