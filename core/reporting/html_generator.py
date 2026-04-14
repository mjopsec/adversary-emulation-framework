"""
HTML Report Generator — menghasilkan laporan self-contained HTML menggunakan Jinja2.
Output adalah file HTML tunggal dengan CSS inline, siap dibuka di browser.
"""

from datetime import datetime, timezone

from jinja2 import Environment, BaseLoader

# ─── Template HTML ────────────────────────────────────────────────────────────

_CAMPAIGN_TEMPLATE = """\
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{ r.campaign_name }} — AEP Report</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', Arial, sans-serif; background: #f4f6f9; color: #222; }
    .cover { background: #1a1f36; color: #fff; padding: 60px 48px 48px; }
    .cover h1 { font-size: 2rem; font-weight: 700; margin-bottom: 8px; }
    .cover .subtitle { color: #a0aec0; font-size: 1rem; margin-bottom: 32px; }
    .cover .meta { display: flex; gap: 32px; flex-wrap: wrap; }
    .cover .meta-item { }
    .cover .meta-item label { font-size: 0.72rem; text-transform: uppercase;
                              letter-spacing: 1px; color: #718096; display: block; }
    .cover .meta-item span { font-size: 0.95rem; color: #e2e8f0; }
    .content { max-width: 1100px; margin: 0 auto; padding: 36px 24px; }
    .section { background: #fff; border-radius: 10px; box-shadow: 0 1px 4px rgba(0,0,0,.08);
               padding: 28px 32px; margin-bottom: 24px; }
    .section h2 { font-size: 1.1rem; font-weight: 700; color: #1a1f36;
                  border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; margin-bottom: 20px; }
    .cards { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 8px; }
    .card { flex: 1; min-width: 150px; border-radius: 8px; padding: 20px 24px;
            background: #f7fafc; border: 1px solid #e2e8f0; }
    .card .num { font-size: 2rem; font-weight: 700; line-height: 1; }
    .card .lbl { font-size: 0.78rem; color: #718096; margin-top: 4px; text-transform: uppercase; }
    .card.success .num { color: #38a169; }
    .card.failed .num  { color: #e53e3e; }
    .card.warn .num    { color: #d69e2e; }
    .card.info .num    { color: #3182ce; }
    table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
    th { background: #f7fafc; text-align: left; padding: 10px 12px;
         font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.5px;
         color: #718096; border-bottom: 2px solid #e2e8f0; }
    td { padding: 10px 12px; border-bottom: 1px solid #f0f4f8; vertical-align: top; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: #f7fafc; }
    .badge { display: inline-block; padding: 2px 10px; border-radius: 12px;
             font-size: 0.75rem; font-weight: 600; }
    .badge-success  { background: #c6f6d5; color: #276749; }
    .badge-failed   { background: #fed7d7; color: #9b2c2c; }
    .badge-warn     { background: #fefcbf; color: #744210; }
    .badge-info     { background: #bee3f8; color: #2a4365; }
    .badge-critical { background: #1a1f36; color: #fff; }
    .badge-high     { background: #fed7d7; color: #9b2c2c; }
    .badge-medium   { background: #fefcbf; color: #744210; }
    .badge-low      { background: #c6f6d5; color: #276749; }
    .sigma { background: #1a1f36; color: #a0ec9a; padding: 12px 16px;
             border-radius: 6px; font-family: monospace; font-size: 0.78rem;
             white-space: pre-wrap; margin-top: 6px; max-height: 260px; overflow-y: auto; }
    .footer { text-align: center; color: #a0aec0; font-size: 0.78rem; padding: 24px; }
    .gap-row td { background: #fff5f5; }
  </style>
</head>
<body>

<div class="cover">
  <h1>{{ r.campaign_name }}</h1>
  <div class="subtitle">Adversary Emulation Platform — Campaign Report</div>
  <div class="meta">
    <div class="meta-item"><label>Client</label><span>{{ r.client_name }}</span></div>
    <div class="meta-item"><label>Environment</label><span>{{ r.environment_type | upper }}</span></div>
    <div class="meta-item"><label>Engagement</label><span>{{ r.engagement_type | title }}</span></div>
    <div class="meta-item"><label>Status</label><span>{{ r.status | upper }}</span></div>
    <div class="meta-item"><label>Generated</label><span>{{ r.generated_at }}</span></div>
    {% if r.apt_profile_name %}
    <div class="meta-item"><label>APT Profile</label><span>{{ r.apt_profile_name }}</span></div>
    {% endif %}
  </div>
</div>

<div class="content">

  <!-- Executive Summary -->
  <div class="section">
    <h2>Executive Summary</h2>
    <div class="cards">
      <div class="card info">
        <div class="num">{{ r.total_executions }}</div>
        <div class="lbl">Techniques Executed</div>
      </div>
      <div class="card success">
        <div class="num">{{ r.executions_success }}</div>
        <div class="lbl">Successful</div>
      </div>
      <div class="card failed">
        <div class="num">{{ r.executions_failed }}</div>
        <div class="lbl">Failed / Aborted</div>
      </div>
      <div class="card warn">
        <div class="num">{{ r.findings_gap }}</div>
        <div class="lbl">Detection Gaps</div>
      </div>
      <div class="card info">
        <div class="num">{{ r.detection_rate }}%</div>
        <div class="lbl">Detection Rate</div>
      </div>
    </div>
  </div>

  <!-- Execution Timeline -->
  <div class="section">
    <h2>Execution Timeline</h2>
    <table>
      <thead>
        <tr>
          <th>#</th><th>Technique</th><th>Name</th><th>Target</th>
          <th>Status</th><th>Duration</th>
        </tr>
      </thead>
      <tbody>
        {% for ex in r.executions %}
        <tr>
          <td>{{ loop.index }}</td>
          <td><strong>{{ ex.technique_id }}</strong></td>
          <td>{{ ex.technique_name or '—' }}</td>
          <td>{{ ex.target or '—' }}</td>
          <td>
            {% if ex.status == 'success' %}<span class="badge badge-success">success</span>
            {% elif ex.status in ('failed', 'aborted') %}<span class="badge badge-failed">{{ ex.status }}</span>
            {% elif ex.status == 'partial' %}<span class="badge badge-warn">partial</span>
            {% else %}<span class="badge badge-info">{{ ex.status }}</span>{% endif %}
          </td>
          <td>{{ "%.1f s"|format(ex.duration_seconds) if ex.duration_seconds else '—' }}</td>
        </tr>
        {% else %}
        <tr><td colspan="6" style="color:#a0aec0;text-align:center">Belum ada eksekusi.</td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <!-- Findings & Gaps -->
  {% if r.findings %}
  <div class="section">
    <h2>Findings &amp; Detection Gaps</h2>
    <table>
      <thead>
        <tr>
          <th>Technique</th><th>Severity</th><th>Detected</th>
          <th>Quality</th><th>Gap Description</th><th>Remediation</th>
        </tr>
      </thead>
      <tbody>
        {% for f in r.findings %}
        <tr {% if f.is_gap %}class="gap-row"{% endif %}>
          <td><strong>{{ f.technique_id }}</strong><br>
            <span style="color:#718096;font-size:0.8rem">{{ f.technique_name or '' }}</span></td>
          <td><span class="badge badge-{{ f.severity }}">{{ f.severity }}</span></td>
          <td>
            {% if f.detected %}<span class="badge badge-success">Yes</span>
            {% else %}<span class="badge badge-failed">No</span>{% endif %}
          </td>
          <td>{{ f.detection_quality }}</td>
          <td>{{ f.gap_description or '—' }}</td>
          <td>{{ f.remediation_recommendation or '—' }}</td>
        </tr>
        {% if f.sigma_rule %}
        <tr {% if f.is_gap %}class="gap-row"{% endif %}>
          <td colspan="6">
            <strong style="font-size:0.78rem;color:#4a5568">Sigma Rule Hint:</strong>
            <div class="sigma">{{ f.sigma_rule }}</div>
          </td>
        </tr>
        {% endif %}
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

</div>

<div class="footer">
  Generated by AEP — Adversary Emulation Platform &nbsp;|&nbsp; {{ r.generated_at }}
</div>
</body>
</html>
"""

_PURPLE_TEMPLATE = """\
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{ r.session_name }} — Purple Team Report</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', Arial, sans-serif; background: #f4f6f9; color: #222; }
    .cover { background: #2d3748; color: #fff; padding: 60px 48px 48px; }
    .cover h1 { font-size: 2rem; font-weight: 700; margin-bottom: 8px; }
    .cover .subtitle { color: #a0aec0; font-size: 1rem; margin-bottom: 32px; }
    .cover .meta { display: flex; gap: 32px; flex-wrap: wrap; }
    .cover .meta-item label { font-size: 0.72rem; text-transform: uppercase;
                              letter-spacing: 1px; color: #718096; display: block; }
    .cover .meta-item span { font-size: 0.95rem; color: #e2e8f0; }
    .content { max-width: 1100px; margin: 0 auto; padding: 36px 24px; }
    .section { background: #fff; border-radius: 10px; box-shadow: 0 1px 4px rgba(0,0,0,.08);
               padding: 28px 32px; margin-bottom: 24px; }
    .section h2 { font-size: 1.1rem; font-weight: 700; color: #2d3748;
                  border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; margin-bottom: 20px; }
    .cards { display: flex; gap: 16px; flex-wrap: wrap; }
    .card { flex: 1; min-width: 140px; border-radius: 8px; padding: 20px 24px;
            background: #f7fafc; border: 1px solid #e2e8f0; }
    .card .num { font-size: 2rem; font-weight: 700; line-height: 1; }
    .card .lbl { font-size: 0.78rem; color: #718096; margin-top: 4px; text-transform: uppercase; }
    .card.green .num  { color: #38a169; }
    .card.red .num    { color: #e53e3e; }
    .card.yellow .num { color: #d69e2e; }
    .card.blue .num   { color: #3182ce; }
    .card.purple .num { color: #805ad5; }
    table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
    th { background: #f7fafc; text-align: left; padding: 10px 12px;
         font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.5px;
         color: #718096; border-bottom: 2px solid #e2e8f0; }
    td { padding: 10px 12px; border-bottom: 1px solid #f0f4f8; vertical-align: top; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: #f7fafc; }
    .badge { display: inline-block; padding: 2px 10px; border-radius: 12px;
             font-size: 0.75rem; font-weight: 600; }
    .badge-detected  { background: #c6f6d5; color: #276749; }
    .badge-blocked   { background: #bee3f8; color: #2a4365; }
    .badge-partial   { background: #fefcbf; color: #744210; }
    .badge-missed    { background: #fed7d7; color: #9b2c2c; }
    .badge-fp        { background: #e9d8fd; color: #553c9a; }
    .badge-critical  { background: #1a1f36; color: #fff; }
    .badge-high      { background: #fed7d7; color: #9b2c2c; }
    .badge-medium    { background: #fefcbf; color: #744210; }
    .badge-low       { background: #c6f6d5; color: #276749; }
    .sigma { background: #1a1f36; color: #a0ec9a; padding: 12px 16px;
             border-radius: 6px; font-family: monospace; font-size: 0.78rem;
             white-space: pre-wrap; margin-top: 6px; max-height: 260px; overflow-y: auto; }
    .gap-row td { background: #fff5f5; }
    .rec-card { border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px 20px;
                margin-bottom: 12px; }
    .rec-card .priority { font-size: 0.7rem; font-weight: 700; text-transform: uppercase;
                          letter-spacing: 1px; color: #718096; margin-bottom: 4px; }
    .rec-card h3 { font-size: 0.95rem; color: #2d3748; margin-bottom: 8px; }
    .rec-card ul { padding-left: 18px; font-size: 0.85rem; color: #4a5568; }
    .tactic-bar { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
    .tactic-name { width: 180px; font-size: 0.82rem; color: #4a5568; }
    .tactic-track { flex: 1; background: #e2e8f0; border-radius: 4px; height: 10px; }
    .tactic-fill { height: 10px; border-radius: 4px; background: #38a169; }
    .tactic-pct { width: 45px; text-align: right; font-size: 0.8rem; color: #718096; }
    .footer { text-align: center; color: #a0aec0; font-size: 0.78rem; padding: 24px; }
  </style>
</head>
<body>

<div class="cover">
  <h1>{{ r.session_name }}</h1>
  <div class="subtitle">Adversary Emulation Platform — Purple Team Report</div>
  <div class="meta">
    <div class="meta-item"><label>Environment</label><span>{{ r.environment | upper }}</span></div>
    <div class="meta-item"><label>Red Team Lead</label><span>{{ r.red_team_lead or '—' }}</span></div>
    <div class="meta-item"><label>Blue Team Lead</label><span>{{ r.blue_team_lead or '—' }}</span></div>
    <div class="meta-item"><label>Facilitator</label><span>{{ r.facilitator or '—' }}</span></div>
    <div class="meta-item"><label>Generated</label><span>{{ r.generated_at }}</span></div>
  </div>
</div>

<div class="content">

  <!-- Coverage Summary -->
  <div class="section">
    <h2>Detection Coverage Summary</h2>
    <div class="cards">
      <div class="card green">
        <div class="num">{{ "%.0f"|format(r.detection_coverage * 100) }}%</div>
        <div class="lbl">Detection Coverage</div>
      </div>
      <div class="card blue">
        <div class="num">{{ r.total_events }}</div>
        <div class="lbl">Total Events</div>
      </div>
      <div class="card green">
        <div class="num">{{ r.detected_count }}</div>
        <div class="lbl">Detected / Blocked</div>
      </div>
      <div class="card red">
        <div class="num">{{ r.gap_count }}</div>
        <div class="lbl">Gaps (Missed)</div>
      </div>
      {% if r.mttd_seconds %}
      <div class="card purple">
        <div class="num">{{ "%.0f"|format(r.mttd_seconds) }}s</div>
        <div class="lbl">Avg MTTD</div>
      </div>
      {% endif %}
    </div>
  </div>

  <!-- Coverage by Tactic -->
  {% if r.coverage_by_tactic %}
  <div class="section">
    <h2>Coverage by Tactic</h2>
    {% for tactic, pct in r.coverage_by_tactic.items() %}
    <div class="tactic-bar">
      <div class="tactic-name">{{ tactic | replace('_', ' ') | title }}</div>
      <div class="tactic-track">
        <div class="tactic-fill" style="width:{{ [pct * 100, 100]|min }}%"></div>
      </div>
      <div class="tactic-pct">{{ "%.0f"|format(pct * 100) }}%</div>
    </div>
    {% endfor %}
  </div>
  {% endif %}

  <!-- Events Detail -->
  <div class="section">
    <h2>Event Detail</h2>
    <table>
      <thead>
        <tr>
          <th>#</th><th>Technique</th><th>Tactic</th><th>Target</th>
          <th>Blue Response</th><th>Severity</th><th>Latency</th>
        </tr>
      </thead>
      <tbody>
        {% for ev in r.events %}
        <tr {% if ev.is_gap %}class="gap-row"{% endif %}>
          <td>{{ loop.index }}</td>
          <td><strong>{{ ev.technique_id }}</strong><br>
            <span style="color:#718096;font-size:0.8rem">{{ ev.technique_name or '' }}</span></td>
          <td>{{ ev.tactic or '—' }}</td>
          <td>{{ ev.target or '—' }}</td>
          <td>
            {% if ev.blue_response == 'detected' %}<span class="badge badge-detected">detected</span>
            {% elif ev.blue_response == 'blocked' %}<span class="badge badge-blocked">blocked</span>
            {% elif ev.blue_response == 'partial' %}<span class="badge badge-partial">partial</span>
            {% elif ev.blue_response == 'missed' %}<span class="badge badge-missed">missed</span>
            {% elif ev.blue_response == 'false_positive' %}<span class="badge badge-fp">false positive</span>
            {% else %}<span class="badge" style="background:#e2e8f0;color:#4a5568">pending</span>{% endif %}
          </td>
          <td>
            {% if ev.gap_severity %}
            <span class="badge badge-{{ ev.gap_severity }}">{{ ev.gap_severity }}</span>
            {% else %}—{% endif %}
          </td>
          <td>{{ "%.0f s"|format(ev.detection_latency_seconds) if ev.detection_latency_seconds else '—' }}</td>
        </tr>
        {% if ev.sigma_rule_hint %}
        <tr {% if ev.is_gap %}class="gap-row"{% endif %}>
          <td colspan="7">
            <strong style="font-size:0.78rem;color:#4a5568">Sigma Rule Hint:</strong>
            <div class="sigma">{{ ev.sigma_rule_hint }}</div>
          </td>
        </tr>
        {% endif %}
        {% endfor %}
      </tbody>
    </table>
  </div>

  <!-- Recommendations -->
  {% if r.recommendations %}
  <div class="section">
    <h2>Recommendations (Priority Order)</h2>
    {% for rec in r.recommendations %}
    <div class="rec-card">
      <div class="priority">Priority {{ rec.priority }} &nbsp;|&nbsp; {{ rec.technique_id }}
        {% if rec.gap_severity %}&nbsp;|&nbsp;
          <span class="badge badge-{{ rec.gap_severity }}">{{ rec.gap_severity }}</span>
        {% endif %}
      </div>
      <h3>{{ rec.title }}</h3>
      <ul>
        {% for step in rec.steps %}
        <li>{{ step }}</li>
        {% endfor %}
      </ul>
    </div>
    {% endfor %}
  </div>
  {% endif %}

</div>

<div class="footer">
  Generated by AEP — Adversary Emulation Platform &nbsp;|&nbsp; {{ r.generated_at }}
</div>
</body>
</html>
"""

# ─── Jinja2 Environment ───────────────────────────────────────────────────────

_jinja_env = Environment(loader=BaseLoader(), autoescape=True)
_campaign_tmpl = _jinja_env.from_string(_CAMPAIGN_TEMPLATE)
_purple_tmpl = _jinja_env.from_string(_PURPLE_TEMPLATE)


# ─── Public Functions ─────────────────────────────────────────────────────────

def generate_campaign_html(report_data: dict) -> str:
    """
    Render laporan kampanye sebagai HTML self-contained.

    Args:
        report_data: Dict yang dikembalikan oleh ReportGenerator.generate_json_report()
                     ditambah field tambahan: executions, findings (list of obj/dict)

    Returns:
        String HTML lengkap.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    campaign = report_data.get("campaign", {})
    summary = report_data.get("summary", {})

    ctx = _HtmlCampaignContext(
        campaign_name=campaign.get("name", "Unnamed Campaign"),
        client_name=campaign.get("client", "—"),
        environment_type=campaign.get("environment_type", "—"),
        engagement_type=campaign.get("engagement_type", "—"),
        status=campaign.get("status", "—"),
        apt_profile_name=campaign.get("apt_profile_name"),
        generated_at=now,
        total_executions=summary.get("total_techniques_executed", 0),
        executions_success=summary.get("detected", 0),
        executions_failed=summary.get("not_detected", 0),
        findings_gap=sum(summary.get("gaps_by_severity", {}).values()),
        detection_rate=summary.get("detection_rate_percent", 0),
        executions=report_data.get("attack_path", []),
        findings=report_data.get("findings", []),
    )
    return _campaign_tmpl.render(r=ctx)


def generate_purple_html(report_dict: dict) -> str:
    """
    Render laporan purple team sebagai HTML self-contained.

    Args:
        report_dict: Dict dari PurpleSessionReport.to_dict()

    Returns:
        String HTML lengkap.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    ctx = _PurpleHtmlContext(report_dict, now)
    return _purple_tmpl.render(r=ctx)


# ─── Context Wrappers ─────────────────────────────────────────────────────────

class _HtmlCampaignContext:
    """Simple namespace untuk template campaign HTML."""

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

    # Bungkus list findings agar template bisa akses .is_gap
    @property
    def findings(self):
        return [_FindingProxy(f) for f in self.__dict__.get("_findings", [])]

    def __init__(self, campaign_name, client_name, environment_type, engagement_type,
                 status, apt_profile_name, generated_at, total_executions,
                 executions_success, executions_failed, findings_gap, detection_rate,
                 executions, findings):
        self.campaign_name = campaign_name
        self.client_name = client_name
        self.environment_type = environment_type
        self.engagement_type = engagement_type
        self.status = status
        self.apt_profile_name = apt_profile_name
        self.generated_at = generated_at
        self.total_executions = total_executions
        self.executions_success = executions_success
        self.executions_failed = executions_failed
        self.findings_gap = findings_gap
        self.detection_rate = detection_rate
        self.executions = [_ExecProxy(e) for e in executions]
        self._findings_raw = findings

    @property
    def findings(self):  # type: ignore[override]
        return [_FindingProxy(f) for f in self._findings_raw]


class _ExecProxy:
    """Proxy untuk item attack_path (dict)."""

    def __init__(self, d: dict):
        self.technique_id = d.get("technique_id", "")
        self.technique_name = d.get("technique_name")
        self.target = d.get("target")
        self.status = d.get("status", "pending")
        self.duration_seconds = d.get("duration_seconds")


class _FindingProxy:
    """Proxy untuk item findings (dict)."""

    def __init__(self, d: dict):
        self.technique_id = d.get("technique_id", "")
        self.technique_name = d.get("technique_name")
        self.severity = d.get("severity", "medium")
        self.detected = d.get("detected", False)
        self.detection_quality = d.get("detection_quality", "none")
        self.gap_description = d.get("gap_description")
        self.remediation_recommendation = d.get("remediation_recommendation")
        self.sigma_rule = d.get("sigma_rule")
        self.is_gap = not self.detected and self.detection_quality == "none"


class _PurpleHtmlContext:
    """Proxy untuk template purple HTML — membungkus PurpleSessionReport.to_dict()."""

    def __init__(self, d: dict, generated_at: str):
        self.session_name = d.get("session_name", "Purple Session")
        self.environment = d.get("environment", "it")
        self.red_team_lead = d.get("red_team_lead")
        self.blue_team_lead = d.get("blue_team_lead")
        self.facilitator = d.get("facilitator")
        self.generated_at = generated_at

        metrics = d.get("metrics", {})
        self.total_events = metrics.get("total_events", 0)
        self.detected_count = metrics.get("detected_count", 0)
        self.gap_count = metrics.get("gap_count", 0)
        self.detection_coverage = metrics.get("detection_coverage", 0.0)
        self.mttd_seconds = metrics.get("mttd_seconds")
        self.coverage_by_tactic = metrics.get("coverage_by_tactic", {})

        self.events = [_PurpleEventProxy(e) for e in d.get("events", [])]
        self.recommendations = [_RecProxy(r) for r in d.get("recommendations", [])]


class _PurpleEventProxy:
    def __init__(self, d: dict):
        self.technique_id = d.get("technique_id", "")
        self.technique_name = d.get("technique_name")
        self.tactic = d.get("tactic")
        self.target = d.get("target")
        self.blue_response = d.get("blue_response")
        self.is_gap = d.get("is_gap", False)
        self.gap_severity = d.get("gap_severity")
        self.detection_latency_seconds = d.get("detection_latency_seconds")
        self.sigma_rule_hint = d.get("sigma_rule_hint")


class _RecProxy:
    def __init__(self, d: dict):
        self.priority = d.get("priority", 99)
        self.technique_id = d.get("technique_id", "")
        self.title = d.get("title", "")
        self.gap_severity = d.get("gap_severity")
        self.steps = d.get("steps", [])
