"""
NexusGuard — Enterprise SOC Platform
Analyst-first SIEM / incident investigation interface.
All backend logic unchanged; this file is a complete UI redesign.
"""
from __future__ import annotations

import json
import os
import time
import tempfile
from datetime import datetime, timezone

import streamlit as st
import streamlit.components.v1 as components

# ── Backend imports (unchanged) ────────────────────────────────────────────────
from agent.fallback_report import build_fallback_report
from agent.incident_chat import chat_about_incident
from agent.openai_client import chat_completion, is_llm_configured
from agent.report_generator import generate_report
from connectors import neo4j_graph
from connectors.github_live_connector import GitHubLiveConnector, GitHubLiveConnectorError
from connectors.github_raw_feed_connector import (
    GitHubRawFeedConnector,
    GitHubRawFeedConnectorError,
)
from connectors.macos_logs_connector import MacOSLogsConnector, MacOSLogsConnectorError
from correlation.correlator import correlate_detections
from detections.agentic_detector import get_last_agentic_status
from detections.run_all import run_all_detections
from evaluation.runner import run_evidence_triage_workflow
from generators.flog_runner import FlogNotFoundError, FlogRunError, run_flog
from generators.synthetic_live import generate_live_synthetic
from parsers.apache_flog_parser import parse_apache_lines
from parsers.flog_router import parse_flog_output
from parsers.parser_router import parse_auth_file, parse_network_file
from triage.incident_builder import enrich_all_incidents
from triage.mitre_mapper import map_to_mitre
from triage.report_context_builder import build_incident_context
from utils.config import (
    ABUSEIPDB_API_KEY,
    ENV_FILES_LOADED,
    GITHUB_RAW_FEED_FORMAT,
    GITHUB_RAW_FEED_URL,
    GITHUB_REPO,
    GITHUB_TOKEN,
    LLM_API_KEY,
    LLM_BASE_URL,
    LLM_KEY_SOURCE,
    LLM_MODEL,
    NEO4J_BROWSER_URL,
    NEO4J_PASSWORD,
    NEO4J_URI,
    NEO4J_USER,
    VIRUSTOTAL_API_KEY,
)
from utils.exporters import export_incident_csv, export_incident_json

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="NexusGuard SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "data", "sample")

# ══════════════════════════════════════════════════════════════════════════════
# DESIGN SYSTEM — TOKENS
# ══════════════════════════════════════════════════════════════════════════════
SEV_CLR = {
    "critical": "#EF4444",
    "high":     "#F97316",
    "medium":   "#FACC15",
    "low":      "#38BDF8",
    "info":     "#38BDF8",
}
ET_CLR = {
    "authentication_failure": "#EF4444",
    "authentication_success": "#22C55E",
    "network_outbound":       "#38BDF8",
    "network_inbound":        "#5EEAD4",
    "ids_alert":              "#F97316",
}
STATUS_CLR = {
    "New":          "#EF4444",
    "Investigating": "#F97316",
    "Closed":       "#6EE7B7",
    "Escalated":    "#FACC15",
}


# ══════════════════════════════════════════════════════════════════════════════
# CSS — Full enterprise dark design system
# ══════════════════════════════════════════════════════════════════════════════
st.markdown("""
<style>
/* ── Fonts ── */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap');
/* Geist is served via vercel CDN as a web font */
@import url('https://fonts.cdnfonts.com/css/geist') screen;

/* ══════════════════════════════════════
   DESIGN TOKENS
   Background   #0F3D3E
   Sidebar      #092B2C
   Cards        #164E63
   Borders      #134E4A
   Accent       #5EEAD4
   ══════════════════════════════════════ */

/* ── Base reset ── */
html, body, [class*="css"] {
  font-family: 'Inter', 'Geist', system-ui, sans-serif;
  font-size: 14px;
  line-height: 1.5;
  color: #E6FFFA;
}
/* Monospace data strings — IPs, hashes, logs, terminal output */
.mono, code, [data-testid="stCode"], [data-testid="stCodeBlock"],
.ng-ip, .log-line, .hash-str {
  font-family: 'JetBrains Mono', 'IBM Plex Mono', 'Cascadia Code', monospace !important;
}

/* ── App shell — deep charcoal canvas ── */
.stApp {
  background: #0F3D3E !important;
  background-image: none !important;
  background-attachment: fixed !important;
}
.block-container {
  max-width: 1200px !important;
  margin: 0 auto !important;
  padding: 0 28px 28px !important;
  border-left: 1px solid #134E4A !important;
  border-right: 1px solid #134E4A !important;
  min-height: 100vh !important;
}
.stApp > header { display: none !important; }

/* ── Frosted-glass mixin (applied everywhere via shared class) ──
   Background : rgba(22,78,99,0.70)
   Blur       : 12px
   Border     : 1px solid rgba(255,255,255,0.08)               */
.glass {
  background: rgba(22,78,99,0.70) !important;
  backdrop-filter: blur(10px) !important;
  -webkit-backdrop-filter: blur(10px) !important;
  border: 1px solid #134E4A !important;
}

/* ── Sidebar — frosted glass panel ── */
section[data-testid="stSidebar"] {
  background: #092B2C !important;
  backdrop-filter: blur(12px) !important;
  -webkit-backdrop-filter: blur(12px) !important;
  border-right: 1px solid #134E4A !important;
  padding-top: 0 !important;
}
section[data-testid="stSidebar"] > div:first-child { padding-top: 0 !important; }
[data-testid="stSidebarCollapsedControl"] { display: none !important; }

/* Native Streamlit sidebar is replaced by the header menu overlay. */
section[data-testid="stSidebar"],
[data-testid="stSidebarCollapsedControl"] {
  display: none !important;
  width: 0 !important;
  min-width: 0 !important;
}

.ng-menu-button .stButton > button {
  width: 50px !important;
  height: 50px !important;
  min-width: 50px !important;
  padding: 0 !important;
  border-radius: 10px !important;
  border: 1px solid #134E4A !important;
  background: rgba(9,43,44,0.72) !important;
  color: #E6FFFA !important;
  font-size: .75rem !important;
  font-weight: 700 !important;
  letter-spacing: .01em !important;
  box-shadow: 0 0 10px rgba(94,234,212,0.30), 0 8px 24px rgba(0,0,0,0.22) !important;
}
.ng-menu-button .stButton > button:hover {
  border-color: #5EEAD4 !important;
  background: rgba(94,234,212,0.12) !important;
  color: #E6FFFA !important;
  box-shadow: 0 0 10px rgba(94,234,212,0.30), 0 8px 28px rgba(0,0,0,0.28) !important;
}

.ng-menu-overlay {
  position: fixed !important;
  left: 0 !important;
  top: 0 !important;
  right: auto !important;
  bottom: auto !important;
  z-index: 1000;
  width: 350px;
  height: 100vh;
  padding: 22px;
  background: rgba(9,43,44,0.88);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border-right: 1px solid #134E4A;
  box-shadow: 24px 0 80px rgba(0,0,0,0.46);
  animation: ng-slide-menu 180ms ease-out both;
}
.ng-menu-overlay .stButton > button {
  width: 100% !important;
  justify-content: flex-start !important;
  text-align: left !important;
  padding: 12px 14px !important;
  margin-bottom: 6px !important;
  border-radius: 8px !important;
  border: 1px solid #134E4A !important;
  background: rgba(22,78,99,0.70) !important;
  color: #A7F3D0 !important;
  font-size: .86rem !important;
  font-weight: 600 !important;
}
.ng-menu-overlay .stButton > button:hover,
.ng-menu-overlay .stButton > button[kind="primary"] {
  border-color: #5EEAD4 !important;
  background: rgba(94,234,212,0.12) !important;
  color: #E6FFFA !important;
}
.ng-menu-link {
  display: flex;
  align-items: center;
  justify-content: space-between;
  width: 100%;
  padding: 12px 14px;
  margin-bottom: 6px;
  border-radius: 8px;
  border: 1px solid rgba(255,255,255,0.07);
  background: rgba(255,255,255,0.03);
  color: rgba(226,232,240,0.82) !important;
  text-decoration: none !important;
  font-size: .86rem;
  font-weight: 600;
}
.ng-menu-link:hover,
.ng-menu-link.active {
  border-color: rgba(94,234,212,0.24);
  background: rgba(94,234,212,0.08);
  color: #67e8f9 !important;
}
.ng-menu-link span:last-child {
  color: rgba(148,163,184,0.74);
  font-size: .72rem;
}
.ng-menu-x {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 50px;
  height: 50px;
  border-radius: 10px;
  border: 1px solid rgba(94,234,212,0.28);
  color: #dffcff !important;
  text-decoration: none !important;
  font-size: .74rem;
  font-weight: 700;
}
.ng-menu-x:hover {
  background: rgba(94,234,212,0.08);
  border-color: rgba(94,234,212,0.48);
}
.ng-menu-close .stButton > button {
  width: 50px !important;
  height: 50px !important;
  min-width: 50px !important;
  justify-content: center !important;
  text-align: center !important;
  padding: 0 !important;
}
@keyframes ng-slide-menu {
  from { transform: translateX(-24px); opacity: 0; }
  to { transform: translateX(0); opacity: 1; }
}

/* ── Main area ── */
.main-content { padding: 24px 28px; }

/* ═══════════════════════════════════════
   BENTO BOX GRID HELPERS
   Wrap content columns in .bento-grid
   and individual cells in .bento-cell
   ═══════════════════════════════════════ */
.bento-grid {
  display: grid;
  gap: 14px;
  width: 100%;
}
.bento-grid-2 { grid-template-columns: 1fr 1fr; }
.bento-grid-3 { grid-template-columns: 1fr 1fr 1fr; }
.bento-grid-4 { grid-template-columns: repeat(4, 1fr); }
.bento-grid-3-2 { grid-template-columns: 3fr 2fr; }
.bento-grid-2-3 { grid-template-columns: 2fr 3fr; }

/* Bento cells use the glass treatment */
.bento-cell {
  background: rgba(22,78,99,0.70);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border: 1px solid rgba(255,255,255,0.08);
  border-radius: 14px;
  padding: 18px 20px;
  transition: border-color 150ms ease, box-shadow 150ms ease, transform 150ms ease;
  position: relative;
  overflow: hidden;
}
.bento-cell::before {
  content: '';
  position: absolute;
  inset: 0;
  border-radius: 14px;
  background: linear-gradient(135deg, rgba(255,255,255,0.03) 0%, transparent 60%);
  pointer-events: none;
}
.bento-cell:hover {
  border-color: rgba(94,234,212,0.30);
  box-shadow: 0 8px 28px rgba(0,0,0,0.45), 0 0 0 1px rgba(94,234,212,0.10) inset;
  transform: translateY(-1px);
}
/* Wide cell spans full width */
.bento-cell-wide { grid-column: 1 / -1; }
/* Tall cell for workspace rails */
.bento-cell-tall { min-height: 600px; }

/* ── Generic glass card (used in Python via ng-card) ── */
.ng-card {
  background: rgba(22,78,99,0.70);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border: 1px solid rgba(255,255,255,0.08);
  border-radius: 12px;
  padding: 18px 20px;
  margin-bottom: 12px;
  position: relative;
  overflow: hidden;
  transition: border-color 150ms ease, box-shadow 150ms ease, transform 150ms ease;
}
.ng-card::before {
  content: '';
  position: absolute;
  inset: 0;
  border-radius: 12px;
  background: linear-gradient(135deg, rgba(255,255,255,0.03) 0%, transparent 55%);
  pointer-events: none;
}
.ng-card:hover {
  border-color: rgba(94,234,212,0.28);
  box-shadow: 0 6px 22px rgba(0,0,0,0.40);
  transform: translateY(-1px);
}

/* ── Stat / metric cards — glass treatment ── */
div[data-testid="stMetric"] {
  background: rgba(22,78,99,0.70) !important;
  backdrop-filter: blur(12px) !important;
  -webkit-backdrop-filter: blur(12px) !important;
  border: 1px solid rgba(255,255,255,0.08) !important;
  border-radius: 14px !important;
  padding: 18px 22px !important;
  position: relative !important;
  overflow: hidden !important;
  transition: border-color 150ms ease, box-shadow 150ms ease, transform 150ms ease !important;
}
div[data-testid="stMetric"]::before {
  content: '';
  position: absolute;
  inset: 0;
  border-radius: 14px;
  background: linear-gradient(135deg, rgba(255,255,255,0.035) 0%, transparent 60%);
  pointer-events: none;
}
div[data-testid="stMetric"]:hover {
  border-color: rgba(94,234,212,0.30) !important;
  box-shadow: 0 8px 24px rgba(0,0,0,0.40) !important;
  transform: translateY(-2px) !important;
}
div[data-testid="stMetricLabel"] p {
  color: rgba(148,163,184,0.75) !important;
  font-size: .70rem !important;
  font-weight: 700 !important;
  text-transform: uppercase !important;
  letter-spacing: .10em !important;
}
div[data-testid="stMetricValue"] {
  color: #E6FFFA !important;
  font-weight: 800 !important;
  font-size: 2rem !important;
}

/* ── Tabs ── */
.stTabs [data-baseweb="tab-list"] {
  background: transparent !important;
  border-bottom: 1px solid rgba(255,255,255,0.07) !important;
  gap: 0 !important;
  padding: 0 !important;
}
.stTabs [data-baseweb="tab"] {
  padding: 10px 18px !important;
  font-size: .82rem !important;
  font-weight: 600 !important;
  color: rgba(100,116,139,0.85) !important;
  border-bottom: 2px solid transparent !important;
  background: transparent !important;
  border-radius: 0 !important;
  white-space: nowrap !important;
  transition: color 130ms ease !important;
}
.stTabs [data-baseweb="tab"]:hover { color: #A7F3D0 !important; }
.stTabs [aria-selected="true"] {
  color: #5EEAD4 !important;
  border-bottom-color: #5EEAD4 !important;
}
.stTabs [data-baseweb="tab-highlight"],
.stTabs [data-baseweb="tab-border"] { display: none !important; }
.stTabs [data-baseweb="tab-panel"] { padding-top: 18px !important; }

/* ── Buttons ── */
.stButton > button {
  border-radius: 8px !important;
  font-weight: 600 !important;
  font-size: .82rem !important;
  border: 1px solid rgba(255,255,255,0.08) !important;
  background: rgba(22,78,99,0.70) !important;
  backdrop-filter: blur(8px) !important;
  color: #A7F3D0 !important;
  transition: all 130ms ease !important;
}
.stButton > button:hover {
  border-color: rgba(94,234,212,0.40) !important;
  color: #E6FFFA !important;
  background: rgba(30,45,80,0.65) !important;
  box-shadow: 0 4px 14px rgba(0,0,0,0.30) !important;
}
.stButton > button[kind="primary"] {
  background: rgba(94,234,212,0.14) !important;
  backdrop-filter: blur(10px) !important;
  border-color: #5EEAD4 !important;
  color: #E6FFFA !important;
  box-shadow: 0 0 10px rgba(94,234,212,0.30) !important;
}
.stButton > button[kind="primary"]:hover {
  background: rgba(94,234,212,0.24) !important;
  border-color: #5EEAD4 !important;
  color: #E6FFFA !important;
  box-shadow: 0 0 10px rgba(94,234,212,0.30), 0 0 26px rgba(94,234,212,0.18) !important;
}
.stDownloadButton > button {
  border-radius: 8px !important;
  font-weight: 600 !important;
  font-size: .82rem !important;
}

/* ── Inputs — glass style ── */
.stTextInput > div > div > input,
.stSelectbox > div > div,
.stMultiSelect > div > div {
  background: rgba(15,61,62,0.80) !important;
  border: 1px solid rgba(255,255,255,0.08) !important;
  border-radius: 8px !important;
  color: #E6FFFA !important;
  font-size: .84rem !important;
  backdrop-filter: blur(6px) !important;
}
.stTextInput > div > div > input:focus {
  border-color: rgba(94,234,212,0.50) !important;
  box-shadow: 0 0 0 3px rgba(94,234,212,0.14) !important;
}
.stTextInput label, .stSelectbox label, .stMultiSelect label,
.stNumberInput label, .stSlider label, .stRadio label, .stCheckbox label {
  color: rgba(100,116,139,0.80) !important;
  font-size: .78rem !important;
  font-weight: 600 !important;
  text-transform: uppercase !important;
  letter-spacing: .06em !important;
}

/* ── Dataframes — glass surface ── */
.stDataFrame {
  border: 1px solid rgba(255,255,255,0.07) !important;
  border-radius: 12px !important;
  background: rgba(22,78,99,0.50) !important;
  backdrop-filter: blur(8px) !important;
}
.stDataFrame thead th {
  background: rgba(15,61,62,0.70) !important;
  color: rgba(100,116,139,0.85) !important;
  font-size: .70rem !important;
  font-weight: 700 !important;
  text-transform: uppercase !important;
  letter-spacing: .07em !important;
  border-bottom: 1px solid rgba(255,255,255,0.07) !important;
}
.stDataFrame tbody tr:hover {
  background: rgba(94,234,212,0.07) !important;
}

/* ── Progress bar ── */
.stProgress > div > div > div > div { background: #5EEAD4 !important; border-radius: 4px !important; }
.stProgress > div > div > div {
  background: rgba(255,255,255,0.07) !important;
  border-radius: 4px !important;
}

/* ── Expanders — glass ── */
.streamlit-expanderHeader {
  background: rgba(22,78,99,0.70) !important;
  backdrop-filter: blur(12px) !important;
  border: 1px solid rgba(255,255,255,0.08) !important;
  border-radius: 8px !important;
  font-weight: 600 !important;
  font-size: .82rem !important;
  color: #A7F3D0 !important;
}
.streamlit-expanderContent {
  background: rgba(15,61,62,0.65) !important;
  backdrop-filter: blur(10px) !important;
  border: 1px solid rgba(255,255,255,0.07) !important;
  border-top: none !important;
  border-radius: 0 0 8px 8px !important;
}

/* ── Chat — glass bubbles ── */
[data-testid="stChatMessage"] {
  border-radius: 12px !important;
  border: 1px solid rgba(255,255,255,0.08) !important;
  margin-bottom: 8px !important;
  background: rgba(22,78,99,0.65) !important;
  backdrop-filter: blur(10px) !important;
}

/* ── Dividers ── */
hr { border-color: rgba(255,255,255,0.07) !important; margin: 16px 0 !important; }

/* ── Scrollbars ── */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.10); border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.18); }

/* ── Custom component classes ── */
.ng-section-label {
  font-size: .68rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .1em;
  color: rgba(100,116,139,0.75);
  padding-bottom: 8px;
  border-bottom: 1px solid rgba(255,255,255,0.07);
  margin: 20px 0 12px;
}
.ng-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 999px;
  font-size: .68rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .05em;
}
.ng-entity-pill {
  display: inline-block;
  padding: 3px 10px;
  border-radius: 6px;
  font-size: .75rem;
  font-weight: 500;
  border: 1px solid rgba(255,255,255,0.08);
  background: rgba(22,78,99,0.70);
  backdrop-filter: blur(6px);
  color: #A7F3D0;
  margin: 2px;
}
.ng-timeline-row {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 8px 0;
  border-bottom: 1px solid rgba(255,255,255,0.06);
}
.ng-timeline-dot {
  width: 9px; height: 9px;
  border-radius: 50%;
  flex-shrink: 0;
  margin-top: 5px;
}
.ng-stat-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 7px 0;
  border-bottom: 1px solid rgba(255,255,255,0.06);
  font-size: .82rem;
}
.ng-health-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 0;
  font-size: .82rem;
  border-bottom: 1px solid rgba(255,255,255,0.06);
}
.ng-health-dot {
  width: 8px; height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.ng-nav-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 14px;
  border-radius: 8px;
  font-size: .84rem;
  font-weight: 500;
  color: rgba(100,116,139,0.85);
  cursor: pointer;
  transition: all 130ms ease;
  margin-bottom: 2px;
  text-decoration: none;
}
.ng-nav-item:hover {
  background: rgba(255,255,255,0.05);
  color: #A7F3D0;
}
.ng-nav-item.active {
  background: rgba(94,234,212,0.12);
  color: #5EEAD4;
  font-weight: 600;
  border: 1px solid rgba(94,234,212,0.18);
}
.ng-nav-badge {
  margin-left: auto;
  background: rgba(255,255,255,0.07);
  color: #A7F3D0;
  font-size: .65rem;
  font-weight: 700;
  padding: 1px 6px;
  border-radius: 999px;
}
.ng-nav-badge.danger { background: rgba(239,68,68,.18); color: #EF4444; }
.ng-top-header {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 28px;
  background: rgba(22,78,99,0.85);
  backdrop-filter: blur(14px);
  -webkit-backdrop-filter: blur(14px);
  border-bottom: 1px solid rgba(255,255,255,0.07);
  position: sticky;
  top: 0;
  z-index: 100;
}
.ng-logo {
  font-size: 1.05rem;
  font-weight: 800;
  color: #E6FFFA;
  letter-spacing: -.01em;
}
.ng-logo span { color: #5EEAD4; }
.ng-page-title {
  font-size: 1.15rem;
  font-weight: 700;
  color: #E6FFFA;
  margin: 0 0 4px;
}
.ng-page-subtitle {
  font-size: .78rem;
  color: rgba(100,116,139,0.80);
  margin: 0;
}
/* ── Incident workspace panels — glass rails ── */
.ng-workspace-rail {
  background: rgba(22,78,99,0.70);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border-right: 1px solid rgba(255,255,255,0.08);
  border-radius: 14px 0 0 14px;
  padding: 16px 14px;
  height: 100%;
  min-height: 600px;
}
.ng-workspace-center {
  padding: 0 20px;
}
.ng-workspace-right {
  background: rgba(22,78,99,0.70);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border-left: 1px solid rgba(255,255,255,0.08);
  border-radius: 0 14px 14px 0;
  padding: 16px 14px;
}
/* ── Evidence cards ── */
.ng-evidence-card {
  background: rgba(22,78,99,0.60);
  backdrop-filter: blur(10px);
  border: 1px solid rgba(255,255,255,0.08);
  border-radius: 10px;
  padding: 14px 16px;
  margin-bottom: 10px;
  transition: border-color 130ms ease, box-shadow 130ms ease;
}
.ng-evidence-card:hover {
  border-color: rgba(94,234,212,0.30);
  box-shadow: 0 4px 16px rgba(0,0,0,0.30);
}
.ng-mitre-pill {
  display: inline-block;
  padding: 3px 10px;
  border-radius: 6px;
  font-size: .72rem;
  font-weight: 600;
  margin: 3px 3px 3px 0;
}
.ng-quick-action {
  display: inline-block;
  padding: 5px 12px;
  border-radius: 7px;
  font-size: .78rem;
  font-weight: 600;
  border: 1px solid rgba(255,255,255,0.08);
  background: rgba(22,78,99,0.70);
  backdrop-filter: blur(6px);
  color: #A7F3D0;
  cursor: pointer;
  transition: all 130ms;
  margin: 3px 3px 3px 0;
}

/* ══════════════════════════════════════════════════════════
   COMMAND PALETTE — centered monospace search bar
   ══════════════════════════════════════════════════════════ */
input[aria-label="Global search"],
input[placeholder*="Search  ·"] {
  font-family: 'JetBrains Mono', 'IBM Plex Mono', monospace !important;
  font-size: .82rem !important;
  letter-spacing: .025em !important;
  text-align: center !important;
  background: rgba(6,9,15,0.95) !important;
  border: 1px solid rgba(94,234,212,0.15) !important;
  border-radius: 10px !important;
  color: rgba(224,232,244,0.90) !important;
  padding-left: 18px !important;
  padding-right: 18px !important;
  height: 40px !important;
  transition: border-color 150ms ease, box-shadow 150ms ease !important;
}
input[aria-label="Global search"]::placeholder,
input[placeholder*="Search  ·"]::placeholder {
  color: rgba(100,116,139,0.42) !important;
  text-align: center !important;
  letter-spacing: .04em !important;
}
input[aria-label="Global search"]:focus,
input[placeholder*="Search  ·"]:focus {
  border-color: rgba(94,234,212,0.42) !important;
  box-shadow: 0 0 0 3px rgba(94,234,212,0.07),
              0 0 24px rgba(94,234,212,0.08) !important;
}

/* ══════════════════════════════════════════════════════════
   LED STATUS INDICATORS
   ══════════════════════════════════════════════════════════ */
.ng-led {
  width: 7px; height: 7px;
  border-radius: 50%;
  display: inline-block;
  flex-shrink: 0;
}
.ng-led-ok {
  background: #22C55E;
  box-shadow: 0 0 5px 2px rgba(34,197,94,0.70),
              0 0 11px 4px rgba(34,197,94,0.28);
}
.ng-led-warn {
  background: #FACC15;
  box-shadow: 0 0 5px 2px rgba(250,204,21,0.70),
              0 0 11px 4px rgba(250,204,21,0.28);
}
.ng-led-err {
  background: #EF4444;
  box-shadow: 0 0 5px 2px rgba(239,68,68,0.70),
              0 0 11px 4px rgba(239,68,68,0.28);
}
@keyframes ng-led-blink {
  0%, 100% { opacity: 1; }
  50%       { opacity: 0.35; }
}
.ng-led-err { animation: ng-led-blink 1.9s ease-in-out infinite; }

/* Health cluster strip in top header */
.ng-health-cluster {
  display: flex;
  align-items: center;
  gap: 5px;
  padding: 8px 0;
  justify-content: flex-end;
  flex-wrap: wrap;
}
.ng-health-chip {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 3px 9px;
  border-radius: 20px;
  background: rgba(255,255,255,0.04);
  border: 1px solid rgba(255,255,255,0.07);
  font-size: .65rem;
  font-weight: 700;
  color: rgba(148,163,184,0.78);
  letter-spacing: .05em;
  white-space: nowrap;
}
.ng-crit-indicator {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 3px 10px;
  border-radius: 20px;
  background: rgba(239,68,68,.10);
  border: 1px solid rgba(239,68,68,.30);
  color: #EF4444;
  font-size: .68rem;
  font-weight: 700;
  white-space: nowrap;
}

/* ══════════════════════════════════════════════════════════
   NEON CYAN — RUN BUTTON + PULSE ANIMATION
   ══════════════════════════════════════════════════════════ */
@keyframes ng-pulse-cyan {
  0%, 100% {
    box-shadow: 0 0 0 0   rgba(94,234,212,0.45),
                0 4px 14px rgba(0,0,0,0.38);
  }
  50% {
    box-shadow: 0 0 0 9px  rgba(94,234,212,0.00),
                0 4px 24px rgba(94,234,212,0.32);
  }
}
/* Scope to primary buttons inside ANY expander (pipeline is the only primary) */
[data-testid="stExpander"] .stButton > button[kind="primary"] {
  background: rgba(94,234,212,0.12) !important;
  border: 1.5px solid #5EEAD4 !important;
  color: #5EEAD4 !important;
  font-family: 'JetBrains Mono', monospace !important;
  font-weight: 700 !important;
  font-size: .87rem !important;
  letter-spacing: .07em !important;
  box-shadow: 0 0 10px rgba(94,234,212,0.30) !important;
  text-shadow: 0 0 10px rgba(94,234,212,0.45) !important;
  animation: ng-pulse-cyan 2.5s ease-in-out infinite !important;
  border-radius: 9px !important;
}
[data-testid="stExpander"] .stButton > button[kind="primary"]:hover {
  background: rgba(94,234,212,0.20) !important;
  box-shadow: 0 0 10px rgba(94,234,212,0.30), 0 0 26px rgba(94,234,212,0.18) !important;
  animation: none !important;
  color: #E6FFFA !important;
}

/* ── Utility bar expander chrome ── */
[data-testid="stExpander"] {
  border: 1px solid rgba(94,234,212,0.14) !important;
  border-radius: 12px !important;
  overflow: hidden !important;
  margin-bottom: 20px !important;
}
.streamlit-expanderHeader {
  background: rgba(94,234,212,0.025) !important;
  border-color: rgba(94,234,212,0.14) !important;
  color: rgba(0,220,220,0.80) !important;
  font-family: 'JetBrains Mono', 'IBM Plex Mono', monospace !important;
  font-size: .80rem !important;
  letter-spacing: .06em !important;
}
.streamlit-expanderContent {
  background: rgba(15,61,62,0.70) !important;
  border-top: 1px solid rgba(94,234,212,0.08) !important;
}

/* ══════════════════════════════════════════════════════════
   DASHBOARD SKELETON MODULES
   ══════════════════════════════════════════════════════════ */
.ng-skeleton-label {
  font-size: .62rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .12em;
  color: rgba(100,116,139,0.50);
  margin-bottom: 16px;
  display: flex;
  align-items: center;
  gap: 7px;
}
.ng-feed-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 0;
  border-bottom: 1px solid rgba(255,255,255,0.055);
  font-size: .78rem;
}
.ng-feed-row:last-child { border-bottom: none; }
.ng-feed-icon {
  width: 28px; height: 28px;
  border-radius: 7px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: .82rem;
  flex-shrink: 0;
}
.ng-asset-table {
  width: 100%;
  border-collapse: collapse;
  font-size: .78rem;
}
.ng-asset-table th {
  font-size: .63rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .10em;
  color: rgba(100,116,139,0.55);
  padding: 5px 8px 8px;
  border-bottom: 1px solid rgba(255,255,255,0.07);
  text-align: left;
}
.ng-asset-table td {
  padding: 7px 8px;
  border-bottom: 1px solid rgba(255,255,255,0.04);
  color: #A7F3D0;
  vertical-align: middle;
}
.ng-asset-table tr:last-child td { border-bottom: none; }
.ng-ip {
  font-family: 'JetBrains Mono', 'IBM Plex Mono', monospace;
  font-size: .75rem;
  color: #5EEAD4;
  letter-spacing: .02em;
}
.ng-sev-flag {
  display: inline-block;
  padding: 1px 7px;
  border-radius: 4px;
  font-size: .63rem;
  font-weight: 700;
  letter-spacing: .04em;
  text-transform: uppercase;
}

/* ── Full sidebar nav buttons (default / full state) ──
   Slim-state injected CSS overrides these for icon-strip mode.
   Closed-state injected CSS overrides for the floating hamburger. */
section[data-testid="stSidebar"] .stButton > button {
  text-align: left !important;
  justify-content: flex-start !important;
  padding: 9px 14px !important;
  font-size: .84rem !important;
  font-weight: 500 !important;
  border-radius: 8px !important;
  margin-bottom: 2px !important;
  background: transparent !important;
  border-color: transparent !important;
  color: rgba(100,116,139,0.85) !important;
  backdrop-filter: none !important;
  letter-spacing: .01em !important;
}
section[data-testid="stSidebar"] .stButton > button:hover {
  background: rgba(255,255,255,0.05) !important;
  color: #A7F3D0 !important;
  border-color: transparent !important;
}
section[data-testid="stSidebar"] .stButton > button[kind="primary"] {
  background: rgba(94,234,212,0.12) !important;
  border: 1px solid rgba(94,234,212,0.18) !important;
  color: #5EEAD4 !important;
  font-weight: 600 !important;
  backdrop-filter: blur(4px) !important;
  text-align: left !important;
  justify-content: flex-start !important;
}
section[data-testid="stSidebar"] .stButton > button[kind="primary"]:hover {
  background: rgba(94,234,212,0.18) !important;
  box-shadow: 0 0 12px rgba(94,234,212,0.18) !important;
}

/* ══════════════════════════════════════════════════════════
   SIDEBAR STATE ENGINE
   Three states: full (240px) | slim (64px) | closed (0px)
   State-dependent width CSS is injected from Python per render.
   This block holds base rules that apply across all states.
   ══════════════════════════════════════════════════════════ */
section[data-testid="stSidebar"] {
  /* Smooth width transition (fires when Streamlit re-renders w/ new CSS) */
  transition: width 260ms cubic-bezier(0.4,0,0.2,1),
              min-width 260ms cubic-bezier(0.4,0,0.2,1) !important;
}

/* ── SLIM state: compact square icon-only buttons ── */
/* Applied via injected <style> when sidebar_state == "slim" */
.sb-slim section[data-testid="stSidebar"] .stButton > button {
  width: 44px !important;
  height: 44px !important;
  min-width: unset !important;
  border-radius: 10px !important;
  padding: 0 !important;
  font-size: 1.18rem !important;
  line-height: 1 !important;
  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
  margin: 0 auto 3px !important;
  border: 1px solid rgba(255,255,255,0.07) !important;
  background: rgba(22,78,99,0.55) !important;
  color: rgba(148,163,184,0.80) !important;
  transition: all 130ms ease !important;
}
.sb-slim section[data-testid="stSidebar"] .stButton > button:hover {
  border-color: rgba(94,234,212,0.38) !important;
  background: rgba(94,234,212,0.10) !important;
  color: #5EEAD4 !important;
  box-shadow: 0 0 12px rgba(94,234,212,0.18) !important;
}
/* Active page icon in slim mode */
.sb-slim section[data-testid="stSidebar"] .stButton > button[kind="primary"] {
  border-color: rgba(94,234,212,0.45) !important;
  background: rgba(94,234,212,0.14) !important;
  color: #5EEAD4 !important;
  box-shadow: 0 0 12px rgba(94,234,212,0.22) !important;
}

/* ── CLOSED state: sidebar width → 0, one fixed hamburger button ── */
/* overflow: visible lets the fixed button escape the 0-width container */
.sb-closed section[data-testid="stSidebar"] {
  width: 0 !important;
  min-width: 0 !important;
  overflow: visible !important;
  border: none !important;
  background: transparent !important;
  backdrop-filter: none !important;
  padding: 0 !important;
}
.sb-closed section[data-testid="stSidebar"] > div:first-child {
  overflow: visible !important;
  padding: 0 !important;
}
/* The single button inside the 0-width closed sidebar
   → escape via position:fixed and float to viewport top-left */
.sb-closed section[data-testid="stSidebar"] .stButton > button {
  position: fixed !important;
  top: 20px !important;
  left: 20px !important;
  z-index: 300 !important;
  width: 44px !important;
  height: 44px !important;
  border-radius: 10px !important;
  padding: 0 !important;
  font-size: 1.25rem !important;
  background: rgba(94,234,212,0.09) !important;
  border: 1.5px solid rgba(94,234,212,0.50) !important;
  color: #5EEAD4 !important;
  /* Neon glow — always-on so it's impossible to miss */
  box-shadow:
    0 0 10px rgba(94,234,212,0.40),
    0 0 22px rgba(94,234,212,0.16),
    0 2px 12px rgba(0,0,0,0.45) !important;
  animation: ng-pulse-cyan 2.8s ease-in-out infinite !important;
}
.sb-closed section[data-testid="stSidebar"] .stButton > button:hover {
  background: rgba(94,234,212,0.18) !important;
  box-shadow:
    0 0 18px rgba(94,234,212,0.55),
    0 0 38px rgba(94,234,212,0.22) !important;
  animation: none !important;
}
/* Also offset main content when sidebar is closed */
.sb-closed .main .block-container {
  padding-left: 20px !important;
}

/* ── Sidebar collapse-toggle button (inside full/slim sidebar) ── */
.ng-sb-toggle .stButton > button {
  background: rgba(255,255,255,0.03) !important;
  border: 1px solid rgba(255,255,255,0.07) !important;
  color: rgba(100,116,139,0.55) !important;
  font-size: .72rem !important;
  font-weight: 600 !important;
  letter-spacing: .04em !important;
  border-radius: 6px !important;
  padding: 4px 8px !important;
  transition: all 120ms ease !important;
  width: 100% !important;
  text-align: right !important;
}
.ng-sb-toggle .stButton > button:hover {
  color: rgba(148,163,184,0.80) !important;
  border-color: rgba(255,255,255,0.12) !important;
  background: rgba(255,255,255,0.05) !important;
}

/* Final palette pass: keep legacy component rules aligned with the new design. */
html, body, .stApp {
  background: #0F3D3E !important;
  color: #E6FFFA !important;
}

.block-container {
  max-width: 1200px !important;
  margin-left: auto !important;
  margin-right: auto !important;
  border-left: 1px solid #134E4A !important;
  border-right: 1px solid #134E4A !important;
}

.bento-cell,
.ng-card,
.ng-evidence-card,
.ng-workspace-rail,
.ng-workspace-right,
.ng-entity-pill,
.ng-quick-action,
div[data-testid="stMetric"],
[data-testid="stChatMessage"],
[data-testid="stExpander"],
.streamlit-expanderContent,
div[data-testid="stDataFrame"],
.stAlert,
.stButton > button,
.stDownloadButton > button {
  background: rgba(22,78,99,0.70) !important;
  backdrop-filter: blur(10px) !important;
  -webkit-backdrop-filter: blur(10px) !important;
  border-color: #134E4A !important;
  color: #A7F3D0 !important;
}

.stButton > button[kind="primary"],
[data-testid="stExpander"] .stButton > button[kind="primary"] {
  background: rgba(94,234,212,0.14) !important;
  border-color: #5EEAD4 !important;
  color: #E6FFFA !important;
  box-shadow: 0 0 10px rgba(94,234,212,0.30) !important;
}

.stButton > button[kind="primary"]:hover,
[data-testid="stExpander"] .stButton > button[kind="primary"]:hover {
  background: rgba(94,234,212,0.24) !important;
  border-color: #5EEAD4 !important;
  color: #E6FFFA !important;
  box-shadow: 0 0 10px rgba(94,234,212,0.30), 0 0 26px rgba(94,234,212,0.18) !important;
}

p, li, span, label, div {
  color: inherit;
}

.ng-page-title,
h1, h2, h3,
div[data-testid="stMetricValue"] {
  color: #E6FFFA !important;
}

.ng-page-subtitle,
.ng-section-label,
div[data-testid="stMetricLabel"] p,
.stCaptionContainer,
small {
  color: #A7F3D0 !important;
}

.ng-muted,
.ng-stat-row,
.ng-health-chip {
  color: #6EE7B7 !important;
}

.ng-logo span,
a,
.stTabs [aria-selected="true"] {
  color: #5EEAD4 !important;
}

.ng-led-ok {
  background: #22C55E !important;
  box-shadow: 0 0 5px 2px rgba(34,197,94,0.70), 0 0 11px 4px rgba(34,197,94,0.28) !important;
}

.ng-led-err {
  background: #EF4444 !important;
}
</style>
""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def _sc(s: str) -> str:
    return SEV_CLR.get((s or "info").lower(), "#6EE7B7")


def _badge(sev: str, size: str = "sm") -> str:
    s = (sev or "info").lower()
    c = _sc(s)
    pad = "2px 7px" if size == "sm" else "4px 12px"
    fs  = ".68rem"  if size == "sm" else ".76rem"
    return (
        f'<span class="ng-badge" style="color:{c};background:{c}18;'
        f'border:1px solid {c}40;padding:{pad};font-size:{fs};">{s}</span>'
    )


def _status_badge(status: str) -> str:
    c = STATUS_CLR.get(status, "#6EE7B7")
    return (
        f'<span class="ng-badge" style="color:{c};background:{c}18;'
        f'border:1px solid {c}40;padding:2px 8px;font-size:.68rem;">{status}</span>'
    )


def _entity_pill(label: str, val: str, color: str = "#5EEAD4") -> str:
    if not val:
        return ""
    return (
        f'<span style="display:inline-flex;align-items:center;gap:5px;padding:3px 9px;'
        f'border-radius:6px;border:1px solid {color}30;background:{color}0d;'
        f'color:{color};font-size:.74rem;font-weight:500;margin:2px;">'
        f'<span style="font-size:.65rem;color:{color}88;">{label}</span>'
        f'<span style="font-weight:600;">{val}</span></span>'
    )


def _section(icon: str, text: str) -> None:
    st.markdown(
        f'<div class="ng-section-label">{icon}&nbsp;&nbsp;{text}</div>',
        unsafe_allow_html=True,
    )


def _render_knowledge_graph(kg: dict) -> None:
    import math

    nodes = kg.get("nodes") or []
    edges = kg.get("edges") or []
    if not nodes:
        st.caption("No graph structure available for this incident.")
        return

    COLOR_MAP = {
        "incident":   "#2563eb",
        "detection":  "#7c3aed",
        "user":       "#0d9488",
        "host":       "#0891b2",
        "ip":         "#d97706",
        "event_type": "#e11d48",
    }

    W, H = 760, 460
    cx, cy = W / 2, H / 2
    radius = min(180, 82 + len(nodes) * 10)

    positions = {}
    for i, node in enumerate(nodes):
        if node.get("type") == "incident":
            positions[node["id"]] = (cx, cy)
        else:
            angle = (2 * math.pi * i) / len(nodes) - math.pi / 2
            positions[node["id"]] = (
                cx + math.cos(angle) * radius,
                cy + math.sin(angle) * radius,
            )

    def _e(s):
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    def _short(s, n=18):
        s = str(s)
        return s[: n - 1] + "…" if len(s) > n else s

    edge_svg = []
    for edge in edges:
        a = positions.get(str(edge.get("source") or ""))
        b = positions.get(str(edge.get("target") or ""))
        if not a or not b:
            continue
        mx, my = (a[0] + b[0]) / 2, (a[1] + b[1]) / 2
        edge_svg.append(
            f'<line stroke="rgba(94,234,212,0.40)" stroke-width="1.8" '
            f'x1="{a[0]:.1f}" y1="{a[1]:.1f}" x2="{b[0]:.1f}" y2="{b[1]:.1f}" marker-end="url(#arrow)"/>'
            f'<text x="{mx:.1f}" y="{my - 5:.1f}" text-anchor="middle" '
            f'fill="#A7F3D0" font-size="10" font-weight="600">'
            f'{_e(_short(edge.get("relation", "related")))}</text>'
        )

    node_svg = []
    for node in nodes:
        nid = str(node.get("id") or "")
        p = positions.get(nid)
        if not p:
            continue
        r = 34 if node.get("type") == "incident" else 28
        color = COLOR_MAP.get(str(node.get("type") or ""), "#64748b")
        label = _short(node.get("label") or nid)
        ntype = _short(str(node.get("type") or ""), 10)
        node_svg.append(
            f'<g>'
            f'<circle cx="{p[0]:.1f}" cy="{p[1]:.1f}" r="{r}" fill="{color}" '
            f'stroke="rgba(94,234,212,0.50)" stroke-width="2.5"/>'
            f'<text x="{p[0]:.1f}" y="{p[1] + 4:.1f}" text-anchor="middle" '
            f'fill="#fff" font-size="10" font-weight="800">{_e(ntype)}</text>'
            f'<text x="{p[0]:.1f}" y="{p[1] + r + 18:.1f}" text-anchor="middle" '
            f'fill="#E6FFFA" font-size="12" font-weight="700">{_e(label)}</text>'
            f'</g>'
        )

    svg_content = (
        '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" '
        'markerWidth="6" markerHeight="6" orient="auto-start-reverse">'
        '<path d="M 0 0 L 10 5 L 0 10 z" fill="#5EEAD4"/></marker></defs>'
        + "".join(edge_svg)
        + "".join(node_svg)
    )

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"/>
<style>
  body {{ margin:0; padding:0; background:transparent; user-select:none; }}
  #wrap {{ border:1px solid rgba(94,234,212,0.30); border-radius:22px; overflow:hidden;
           background: #092B2C; }}
  svg {{ display:block; width:100%; height:470px; cursor:grab; }}
  svg.dragging {{ cursor:grabbing; }}
</style>
</head>
<body>
<div id="wrap">
  <svg id="g" viewBox="0 0 {W} {H}" preserveAspectRatio="xMidYMid meet">
    <g id="vp">{svg_content}</g>
  </svg>
</div>
<script>
  const svg = document.getElementById('g');
  const vp  = document.getElementById('vp');
  let scale = 1, tx = 0, ty = 0, dragging = false, ox = 0, oy = 0;

  function applyTransform() {{
    vp.setAttribute('transform', `translate(${{tx}},${{ty}}) scale(${{scale}})`);
  }}

  svg.addEventListener('wheel', e => {{
    e.preventDefault();
    const rect = svg.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    const svgW = rect.width, svgH = rect.height;
    const vbW = {W}, vbH = {H};
    const px = (mx / svgW) * vbW;
    const py = (my / svgH) * vbH;
    const delta = e.deltaY < 0 ? 1.12 : 0.89;
    const newScale = Math.max(0.25, Math.min(5, scale * delta));
    tx = px - (px - tx) * (newScale / scale);
    ty = py - (py - ty) * (newScale / scale);
    scale = newScale;
    applyTransform();
  }}, {{ passive: false }});

  svg.addEventListener('mousedown', e => {{
    dragging = true;
    ox = e.clientX - tx;
    oy = e.clientY - ty;
    svg.classList.add('dragging');
  }});
  window.addEventListener('mousemove', e => {{
    if (!dragging) return;
    tx = e.clientX - ox;
    ty = e.clientY - oy;
    applyTransform();
  }});
  window.addEventListener('mouseup', () => {{
    dragging = false;
    svg.classList.remove('dragging');
  }});

  svg.addEventListener('touchstart', e => {{
    if (e.touches.length === 1) {{
      dragging = true;
      ox = e.touches[0].clientX - tx;
      oy = e.touches[0].clientY - ty;
    }}
  }}, {{ passive: true }});
  svg.addEventListener('touchmove', e => {{
    if (dragging && e.touches.length === 1) {{
      tx = e.touches[0].clientX - ox;
      ty = e.touches[0].clientY - oy;
      applyTransform();
    }}
  }}, {{ passive: true }});
  svg.addEventListener('touchend', () => {{ dragging = false; }});

  svg.addEventListener('dblclick', () => {{
    scale = 1; tx = 0; ty = 0; applyTransform();
  }});
</script>
</body></html>"""

    components.html(html, height=490, scrolling=False)


def _etl(t: str) -> str:
    return t.replace("_", " ").title()


def _trace(msg: str) -> None:
    st.session_state.pipeline_trace.append(msg)


@st.cache_resource
def _ui_memory() -> dict:
    return {}


def _save_pipeline_memory() -> None:
    memory = _ui_memory()
    for key in (
        "events",
        "detections",
        "incidents",
        "selected_incident_idx",
        "incident_context",
        "pipeline_run",
        "auth_format",
        "pipeline_trace",
        "evidence_flow_results",
        "detection_engine",
    ):
        memory[key] = st.session_state.get(key)


def _submit_incident_chat(prompt: str) -> None:
    prompt = (prompt or "").strip()
    if not prompt:
        return
    st.session_state.chat_history.append({"role": "user", "content": prompt})
    resp = chat_about_incident(
        st.session_state.incident_context,
        st.session_state.chat_history[:-1],
        prompt,
    )
    st.session_state.chat_history.append({"role": "assistant", "content": resp})


MITRE_CONTEXT = {
    "T1110": {
        "stage": "Credential Access",
        "why": "Repeated failed authentication attempts indicate password guessing, spraying, or brute-force activity.",
        "link": "https://attack.mitre.org/techniques/T1110/",
    },
    "T1078": {
        "stage": "Initial Access / Defense Evasion",
        "why": "A successful login after suspicious failures can indicate use of valid credentials by an attacker.",
        "link": "https://attack.mitre.org/techniques/T1078/",
    },
    "T1071": {
        "stage": "Command and Control",
        "why": "Suspicious outbound traffic can represent application-layer protocol communication to attacker infrastructure.",
        "link": "https://attack.mitre.org/techniques/T1071/",
    },
    "T1041": {
        "stage": "Exfiltration",
        "why": "Outbound communication after compromise may indicate data movement over the same channel used for control.",
        "link": "https://attack.mitre.org/techniques/T1041/",
    },
}


def _mitre_id(technique: str) -> str:
    return (technique or "").split(" - ", 1)[0].strip()


def _mitre_detection_evidence(inc, technique_id: str) -> str:
    words = {
        "T1110": ("failed", "brute", "password", "spray"),
        "T1078": ("success", "valid", "credential", "compromise", "login"),
        "T1071": ("outbound", "c2", "command", "control", "callback", "beacon"),
        "T1041": ("outbound", "exfil", "data", "c2"),
    }.get(technique_id, ())
    matches = []
    for det in inc.detections:
        haystack = " ".join([
            det.detection_type or "",
            det.detection_name or "",
            det.description or "",
            " ".join(det.tags or []),
        ]).lower()
        if any(word in haystack for word in words):
            matches.append(det.detection_name or det.detection_type or det.detection_id)
    return ", ".join(dict.fromkeys(matches)) or "Mapped from correlated incident detections."


def _generate_mitre_llm_context(inc) -> str | None:
    ctx = build_incident_context(inc)
    payload = {
        "incident": {
            "title": inc.title,
            "summary": inc.summary,
            "severity": inc.severity,
            "affected_user": inc.affected_user,
            "affected_host": inc.affected_host,
            "src_ip": inc.primary_src_ip,
            "dst_ip": inc.primary_dst_ip,
        },
        "detections": [
            {
                "type": d.detection_type,
                "name": d.detection_name,
                "description": d.description,
                "severity": d.severity,
                "tags": d.tags,
            }
            for d in inc.detections
        ],
        "mitre_tactics": inc.mitre_tactics,
        "mitre_techniques": inc.mitre_techniques,
        "timeline": ctx.get("timeline", [])[:8],
    }
    return chat_completion(
        [
            {
                "role": "system",
                "content": (
                    "You are a SOC analyst. Explain the MITRE ATT&CK mapping for this incident. "
                    "Use concise markdown. For each technique include: attack stage, why it applies, "
                    "supporting evidence, and an analyst next step. Do not invent evidence."
                ),
            },
            {"role": "user", "content": json.dumps(payload, default=str)},
        ],
        temperature=0.2,
        max_tokens=900,
    )


def _fallback_final_decision_summary(inc, result: dict) -> str:
    fd = result.get("final_decision") or {}
    verifier = result.get("verifier") or {}
    pack = result.get("evidence_pack") or {}
    triage = result.get("triage") or {}
    coverage = (pack.get("coverage_summary") or {}).get("coverage_score", "n/a")
    decision = str(fd.get("final_decision", "defer")).upper()
    reason = fd.get("reason") or "No detailed policy reason was returned."
    policy = fd.get("policy_applied") or "not recorded"
    verifier_state = "valid" if verifier.get("is_valid") else "invalid or incomplete"
    recommended = verifier.get("recommended_final_action") or "not specified"
    claim_count = len(triage.get("claims") or [])
    unsupported = verifier.get("unsupported_claims") or []
    contradictions = verifier.get("contradictions") or []

    risk_line = (
        f"The incident is rated {inc.severity} with a criticality score of "
        f"{inc.criticality_score:.0f}/100."
    )
    decision_line = (
        f"**Final decision: {decision}.** The policy selected this outcome because `{reason}` "
        f"under policy `{policy}`."
    )
    verifier_line = (
        f"The verifier marked the triage as **{verifier_state}**, recommended "
        f"**{recommended}**, and evaluated coverage at **{coverage}**."
    )
    claims_line = f"The triage output contained **{claim_count} cited claim(s)**."
    if unsupported:
        claims_line += " Unsupported claims: " + ", ".join(map(str, unsupported[:4])) + "."
    if contradictions:
        claims_line += " Contradictions: " + ", ".join(map(str, contradictions[:4])) + "."
    next_line = (
        "In short: escalate when evidence is strong and risk is actionable, close when evidence supports "
        "benign/low-risk behavior, and defer when the evidence or verifier result is not strong enough."
    )
    return "\n\n".join([decision_line, risk_line, verifier_line, claims_line, next_line])


def _generate_final_decision_summary(inc, result: dict) -> str:
    fallback = _fallback_final_decision_summary(inc, result)
    if not is_llm_configured():
        return fallback

    fd = result.get("final_decision") or {}
    verifier = result.get("verifier") or {}
    pack = result.get("evidence_pack") or {}
    triage = result.get("triage") or {}
    payload = {
        "incident": {
            "id": inc.incident_id,
            "title": inc.title,
            "summary": inc.summary,
            "severity": inc.severity,
            "criticality_score": inc.criticality_score,
            "affected_user": inc.affected_user,
            "affected_host": inc.affected_host,
            "primary_src_ip": inc.primary_src_ip,
            "primary_dst_ip": inc.primary_dst_ip,
        },
        "final_decision": fd,
        "verifier": verifier,
        "triage": {
            "decision": triage.get("decision"),
            "confidence": triage.get("confidence"),
            "claims": (triage.get("claims") or [])[:6],
            "uncertainty_reasons": triage.get("uncertainty_reasons") or [],
        },
        "coverage_summary": pack.get("coverage_summary") or {},
        "evidence_ids": (triage.get("evidence_ids") or [])[:12],
    }
    summary = chat_completion(
        [
            {
                "role": "system",
                "content": (
                    "You are a SOC triage lead. Summarize why the final evidence-pipeline decision was made. "
                    "Use only the provided payload. Be concise and concrete. Include: final decision, main "
                    "evidence/reasoning, verifier result, policy reason, and what an analyst should do next. "
                    "Use markdown with short bullets."
                ),
            },
            {"role": "user", "content": json.dumps(payload, default=str)},
        ],
        temperature=0.2,
        max_tokens=650,
    )
    return summary or fallback


def _led(ok: bool) -> str:
    """Render a colored LED glow indicator dot."""
    cls = "ng-led-ok" if ok else "ng-led-err"
    return f'<span class="ng-led {cls}"></span>'


def _sparkline_svg(
    points: list,
    color: str = "#5EEAD4",
    width: int = 80,
    height: int = 26,
) -> str:
    """Return an inline SVG polyline sparkline."""
    if len(points) < 2:
        return ""
    mn, mx = min(points), max(points)
    rng = (mx - mn) or 1
    xs = [i * width / (len(points) - 1) for i in range(len(points))]
    ys = [height - 2 - ((p - mn) / rng * (height - 4)) for p in points]
    pts = " ".join(f"{x:.1f},{y:.1f}" for x, y in zip(xs, ys))
    area_pts = f"0,{height} {pts} {width},{height}"
    return (
        f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
        f'xmlns="http://www.w3.org/2000/svg">'
        f'<defs><linearGradient id="sg{id(points)}" x1="0" y1="0" x2="0" y2="1">'
        f'<stop offset="0%" stop-color="{color}" stop-opacity="0.25"/>'
        f'<stop offset="100%" stop-color="{color}" stop-opacity="0"/></linearGradient></defs>'
        f'<polygon points="{area_pts}" fill="url(#sg{id(points)})" />'
        f'<polyline points="{pts}" fill="none" stroke="{color}" '
        f'stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>'
        f'</svg>'
    )


def _donut_svg(
    segments: list,         # list of (value, color, label) tuples
    size: int = 150,
    label_top: str = "—",
    label_bottom: str = "NO DATA",
) -> str:
    """Return an inline SVG donut chart."""
    import math
    total = sum(v for v, *_ in segments) or 1
    cx = cy = size / 2
    r = size / 2 - 22
    stroke_w = 22
    circumference = 2 * math.pi * r
    offset = 0.0
    circles = []
    for item in segments:
        val, color = item[0], item[1]
        frac = val / total
        dash = frac * circumference
        gap  = circumference - dash
        circles.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" '
            f'stroke-width="{stroke_w}" stroke-dasharray="{dash:.3f} {gap:.3f}" '
            f'stroke-dashoffset="{-offset:.3f}" '
            f'transform="rotate(-90 {cx} {cy})" '
            f'stroke-linecap="butt"/>'
        )
        offset += dash
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" '
        f'xmlns="http://www.w3.org/2000/svg">'
        # dark ring background
        f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
        f'stroke="rgba(255,255,255,0.06)" stroke-width="{stroke_w}"/>'
        + "".join(circles) +
        # center labels
        f'<text x="{cx}" y="{cy - 6}" text-anchor="middle" '
        f'fill="#E6FFFA" font-size="20" font-weight="800" '
        f'font-family="Inter,system-ui,sans-serif">{label_top}</text>'
        f'<text x="{cx}" y="{cy + 13}" text-anchor="middle" '
        f'fill="rgba(100,116,139,0.60)" font-size="8.5" '
        f'font-family="Inter,system-ui,sans-serif" letter-spacing="1.8">{label_bottom}</text>'
        f'</svg>'
    )


def _append_web_attack_seed(log_path: str, rows: int = 180) -> int:
    ts = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    suspicious_paths = ["/wp-admin", "/.env", "/phpmyadmin", "/admin", "/login",
                        "/wp-login.php", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"]
    methods = ["GET", "POST", "GET", "GET", "POST", "GET", "GET"]
    lines = []
    for i in range(rows):
        ip     = f"198.51.100.{(i % 6) + 10}"
        path   = suspicious_paths[i % len(suspicious_paths)]
        method = methods[i % len(methods)]
        status = "404"
        if i % 11 == 0: status = "401"
        if i % 29 == 0: status = "403"
        if i % 37 == 0: status = "500"
        lines.append(f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} 342 "-" "Mozilla/5.0 scanner-bot"')
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, "a", encoding="utf-8", errors="ignore") as f:
        f.write("\n".join(lines) + "\n")
    return len(lines)


# ══════════════════════════════════════════════════════════════════════════════
# SESSION STATE
# ══════════════════════════════════════════════════════════════════════════════
_DEFAULTS: dict = {
    "events": [],
    "detections": [],
    "incidents": [],
    "selected_incident_idx": None,
    "incident_context": None,
    "report_text": None,
    "chat_history": [],
    "pipeline_run": False,
    "auth_format": None,
    "report_mode_ai": True,
    "pipeline_trace": [],
    "evidence_flow_results": {},
    "detection_engine": "agentic",
    # UI navigation
    "page": "Dashboard",
    "alert_status": {},      # detection_id -> status string
    "alert_notes": {},       # detection_id -> notes string
    "menu_open": False,
}
for _k, _v in _DEFAULTS.items():
    if _k not in st.session_state:
        st.session_state[_k] = _v

_memory = _ui_memory()
if not st.session_state.pipeline_run and _memory.get("pipeline_run"):
    for _k, _v in _memory.items():
        if _k in _DEFAULTS or _k == "selected_incident_idx":
            st.session_state[_k] = _v


# ══════════════════════════════════════════════════════════════════════════════
# SIDEBAR NAVIGATION
# ══════════════════════════════════════════════════════════════════════════════
# (label, badge_count_key, slim_emoji)
NAV_ITEMS = [
    ("Dashboard",      None,           "▦"),
    ("Detections",     "detections",   "⚡"),
    ("Incidents",      "incidents",    "🛡"),
    ("Investigations", None,           "🔬"),
    ("Reports",        None,           "📋"),
    ("Admin",          None,           "⚙"),
]

_nav_target = st.query_params.get("nav")
if _nav_target in {label for label, _, _ in NAV_ITEMS}:
    st.session_state.page = _nav_target
    st.session_state.menu_open = False
    st.query_params.clear()

# ── Computed values used in the menu and header ────────────────────────────
n_det  = len(st.session_state.detections)
n_inc  = len(st.session_state.incidents)
n_hi   = sum(1 for i in st.session_state.incidents if i.severity in ("high", "critical"))
llm_ok = is_llm_configured()
neo_ok = neo4j_graph.neo4j_configured()
vt_ok  = bool(VIRUSTOTAL_API_KEY)
ab_ok  = bool(ABUSEIPDB_API_KEY)

if st.session_state.menu_open:
    _links_html = []
    for _label, _count_key, _emoji in NAV_ITEMS:
        _badge_val = ""
        if _count_key == "detections" and n_det:
            _badge_val = str(n_det)
        elif _count_key == "incidents" and n_inc:
            _badge_val = str(n_inc)
        _badge_html = f"<span>{_badge_val}</span>" if _badge_val else "<span></span>"
        _active = " active" if st.session_state.page == _label else ""
        _links_html.append(
            f'<a class="ng-menu-link{_active}" href="?nav={_label}" target="_self">'
            f'<span>{_emoji}&nbsp;&nbsp;{_label}</span>{_badge_html}</a>'
        )
    _stats_html = ""
    if st.session_state.pipeline_run:
        _stats_html = (
            f'<div style="margin-top:18px;padding-top:14px;border-top:1px solid rgba(255,255,255,0.08);'
            f'font-size:.76rem;color:rgba(148,163,184,0.78);">'
            f'Events: <b style="color:#E6FFFA;">{len(st.session_state.events)}</b>&nbsp;·&nbsp;'
            f'Alerts: <b style="color:#E6FFFA;">{n_det}</b>&nbsp;·&nbsp;'
            f'Cases: <b style="color:#E6FFFA;">{n_inc}</b></div>'
        )
    st.markdown(
        f"""
        <div class="ng-menu-overlay">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;">
            <div>
              <div class="ng-logo">Nexus<span>Guard</span></div>
              <div style="font-size:.68rem;color:rgba(148,163,184,0.72);letter-spacing:.08em;text-transform:uppercase;margin-top:2px;">
                SOC investigation platform
              </div>
            </div>
            <a class="ng-menu-x" href="?nav={st.session_state.page}" target="_self">Close</a>
          </div>
          {''.join(_links_html)}
          {_stats_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


# ══════════════════════════════════════════════════════════════════════════════
# TOP HEADER BAR
# ══════════════════════════════════════════════════════════════════════════════
page = st.session_state.page
PAGE_META = {
    "Dashboard":      ("Dashboard", "Security operations overview"),
    "Detections":     ("Detections", "Alert triage and management"),
    "Incidents":      ("Incident Workspace", "Deep-dive investigation and triage"),
    "Investigations": ("Investigations", "Evidence pipeline · triage decisions"),
    "Reports":        ("Reports", "Analyst and leadership summaries"),
    "Admin":          ("Admin & Diagnostics", "System configuration and health"),
}
page_title, page_subtitle = PAGE_META.get(page, (page, ""))

# ── Unified global header: menu | title | command palette | time | connector LEDs ──
hc_menu, hc1, hc2, hc3, hc4 = st.columns([0.7, 2.7, 5, 1, 3])

with hc_menu:
    st.markdown('<div class="ng-menu-button">', unsafe_allow_html=True)
    if st.button("Menu", key="header_menu"):
        st.session_state.menu_open = not st.session_state.menu_open
        st.rerun()
    st.markdown("</div>", unsafe_allow_html=True)

with hc1:
    st.markdown(
        f'<div style="padding:12px 0 8px;">'
        f'<div class="ng-page-title">{page_title}</div>'
        f'<div class="ng-page-subtitle">{page_subtitle}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )

with hc2:
    # Command-palette style: wider, monospace placeholder, cyan focus ring
    st.text_input(
        "Global search",
        placeholder="⌘  Search  ·  IP / user / host / hash / domain …",
        label_visibility="collapsed",
        key="global_search",
    )

with hc3:
    st.selectbox(
        "Time range",
        ["Last 1h", "Last 6h", "Last 24h", "Last 7d", "All"],
        index=2,
        label_visibility="collapsed",
        key="time_range",
    )

with hc4:
    # LED health cluster — replaces old text-only connector health in sidebar
    chips = [
        (_led(llm_ok),  "LLM"),
        (_led(neo_ok),  "Graph"),
        (_led(vt_ok),   "VT"),
        (_led(ab_ok),   "Abuse"),
    ]
    chips_html = "".join(
        f'<div class="ng-health-chip">{dot}<span>{label}</span></div>'
        for dot, label in chips
    )
    crit_html = (
        f'<div class="ng-crit-indicator">⚠ {n_hi} Crit</div>'
        if n_hi else ""
    )
    st.markdown(
        f'<div class="ng-health-cluster">{chips_html}{crit_html}</div>',
        unsafe_allow_html=True,
    )

st.markdown("<div style='height:1px;background:rgba(255,255,255,0.07);margin:0 0 20px;'></div>", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# ██████████████████████  PAGES  ██████████████████████████████████████████████
# ══════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────
# PAGE: DASHBOARD
# ─────────────────────────────────────────────────────────────
if page == "Dashboard":

    # ── Utility Bar — Analysis Pipeline ───────────────────────
    with st.expander("⚡  UTILITY  ·  ANALYSIS PIPELINE", expanded=not st.session_state.pipeline_run):
        _section("", "DATA SOURCE")
        ingest_family = st.radio("Source type", ["Demo", "File", "Live"],
                                 horizontal=True, label_visibility="collapsed")
        if ingest_family == "Live":
            source_mode = st.selectbox("Source", [
                "macOS System Logs (last 60m)",
                "macOS Live Logs (short stream)",
                "macOS Live Logs (continuous)",
                "GitHub Raw Feed (poll)",
            ], label_visibility="collapsed")
        elif ingest_family == "File":
            source_mode = st.selectbox("Source", [
                "Upload CSV Files",
                "Local Apache/Nginx Access Log",
            ], label_visibility="collapsed")
        else:
            source_mode = st.selectbox("Source", [
                "Sample Data",
                "Synthetic live (OSS)",
                "OSS: flog (CLI)",
            ], label_visibility="collapsed")

        # ── Source-specific controls ──
        auth_file = net_file = synth_params = flog_params = None
        mac_signal_only = True
        mac_keywords    = None

        if source_mode == "Upload CSV Files":
            uc1, uc2 = st.columns(2)
            with uc1:
                st.caption("Auth log (CSV)")
                auth_file = st.file_uploader("auth", type=["csv"], key="au", label_visibility="collapsed")
            with uc2:
                st.caption("Network / IDS log (CSV)")
                net_file = st.file_uploader("net", type=["csv"], key="nu", label_visibility="collapsed")

        elif source_mode == "Synthetic live (OSS)":
            sy1, sy2, sy3 = st.columns([2, 1, 1])
            with sy1:
                synth_scenario = st.selectbox("Scenario", [
                    "bulk_attack_queue",
                    "demo_reliable_attack",
                    "ransomware_chain",
                    "insider_threat_exfil",
                    "web_rce_c2",
                    "credential_stuffing_ato",
                    "multi_stage_attack",
                    "random_mixed",
                ], format_func=lambda x: {
                    "bulk_attack_queue":       "🗂️ Bulk queue: 10 TP attacks + 3 FP (full demo)",
                    "demo_reliable_attack":    "Reliable demo chain (recommended)",
                    "ransomware_chain":        "Ransomware: phishing → cred dump → encrypt",
                    "insider_threat_exfil":    "Insider threat: after-hours → bulk download → exfil",
                    "web_rce_c2":              "Web RCE: scanning → SQLi → shell → C2",
                    "credential_stuffing_ato": "Credential stuffing: ATO → new admin → backdoor",
                    "multi_stage_attack":      "Multi-stage: brute → login → outbound",
                    "random_mixed":            "Random mixed (noisy, may produce no hits)",
                }[x], index=0, key="synth_sc")
            with sy2:
                synth_window = st.number_input("Window (min)", 10, 240, 60, 5, key="synth_win")
            with sy3:
                synth_noise = st.number_input("Noise", 0, 50, 8, 1, key="synth_noise")
            synth_seed = st.number_input("Seed (0 = random)", 0, 2**31 - 1, 4, 1, key="synth_seed",
                                         help="Use seed=4 for repeatable demos.")
            synth_params = {
                "scenario":       synth_scenario,
                "window_minutes": int(synth_window),
                "noise_events":   int(synth_noise),
                "seed":           None if synth_seed == 0 else int(synth_seed),
            }

        elif source_mode == "OSS: flog (CLI)":
            fg1, fg2, fg3 = st.columns([1.2, 1.2, 1])
            with fg1: flog_n   = st.number_input("Lines", 50, 20000, 400, 50)
            with fg2: flog_fmt = st.selectbox("Format", ["apache_common","apache_combined","apache_error","rfc3164","rfc5424","json"])
            with fg3: flog_docker = st.toggle("Docker", False)
            blend_mvp = st.toggle("Blend MVP attack-chain events", True)
            flog_params = {"number": int(flog_n), "format": flog_fmt,
                           "use_docker": bool(flog_docker), "blend_mvp": bool(blend_mvp)}

        elif source_mode in ("macOS System Logs (last 60m)", "macOS Live Logs (short stream)"):
            mac_signal_only = st.toggle("Signal-only filter", True)
            mac_kw_txt = st.text_input("Keywords", value="sshd,sudo,securityd,networkextension,loginwindow,failed password,authentication,denied,blocked,firewall")
            mac_keywords = [k.strip() for k in mac_kw_txt.split(",") if k.strip()]

        elif source_mode == "macOS Live Logs (continuous)":
            lc1, lc2 = st.columns(2)
            live_iterations  = lc1.number_input("Iterations", 2, 30, 6, 1)
            live_poll_seconds = lc2.number_input("Poll sec/iter", 4, 30, 8, 1)
            mac_signal_only  = st.toggle("Signal-only filter", True)
            mac_kw_txt = st.text_input("Keywords", value="sshd,sudo,securityd,networkextension,loginwindow,failed password,authentication,denied,blocked,firewall", key="mk_cont")
            mac_keywords = [k.strip() for k in mac_kw_txt.split(",") if k.strip()]

        elif source_mode == "GitHub Raw Feed (poll)":
            gr1, gr2, gr3 = st.columns([3, 1, 1])
            gh_raw_url  = gr1.text_input("Feed URL", value=GITHUB_RAW_FEED_URL)
            gh_raw_fmt  = gr2.selectbox("Format", ["jsonl","json","csv"], index=["jsonl","json","csv"].index(GITHUB_RAW_FEED_FORMAT if GITHUB_RAW_FEED_FORMAT in ["jsonl","json","csv"] else "jsonl"))
            gh_raw_iters = gr3.number_input("Iterations", 1, 20, 3, 1)

        elif source_mode == "Local Apache/Nginx Access Log":
            default_local_access = os.path.join(os.path.dirname(__file__), "data", "live", "nginx_access.log")
            l1, l2, l3 = st.columns([3, 1, 1])
            local_access_path   = l1.text_input("Log path", value=default_local_access)
            local_tail_lines    = l2.number_input("Last N lines", 100, 200000, 5000, 100)
            local_poll_iterations = l3.number_input("Iterations", 1, 20, 1, 1)
            if st.button("Inject suspicious web attack seed"):
                try:
                    n = _append_web_attack_seed(local_access_path, rows=180)
                    st.success(f"Added {n} suspicious lines → {local_access_path}")
                except Exception as exc:
                    st.error(f"Seed injection failed: {exc}")

        # ── Detection engine badge ──
        if st.session_state.detection_engine == "rules_fallback":
            st.warning("Running rule-based fallback (no LLM). Check GROQ_API_KEY in .env.", icon="⚠️")

        run_btn = st.button("▶  EXECUTE PIPELINE", type="primary", use_container_width=True)

        if run_btn:
            st.session_state.pipeline_trace = []
            bar = st.progress(0, text="Initialising …")
            _trace(f"Source: {source_mode}")

            if source_mode == "Sample Data":
                with open(os.path.join(SAMPLE_DIR, "auth_linux_sample.csv")) as f: auth_c = f.read()
                with open(os.path.join(SAMPLE_DIR, "network_ids_sample.csv")) as f: net_c  = f.read()
                bar.progress(15, "Parsing auth logs …")
                auth_ev, fmt = parse_auth_file(auth_c)
                bar.progress(30, "Parsing network logs …")
                net_ev = parse_network_file(net_c)
                all_events = auth_ev + net_ev
                st.session_state.auth_format = fmt
                _trace(f"Parse: auth={len(auth_ev)}, net={len(net_ev)}")

            elif source_mode == "Upload CSV Files":
                if not (auth_file and net_file):
                    st.error("Upload both CSV files."); st.stop()
                bar.progress(15, "Parsing auth logs …")
                auth_ev, fmt = parse_auth_file(auth_file.read().decode("utf-8"))
                bar.progress(30, "Parsing network logs …")
                net_ev = parse_network_file(net_file.read().decode("utf-8"))
                all_events = auth_ev + net_ev
                st.session_state.auth_format = fmt

            elif source_mode == "Synthetic live (OSS)":
                bar.progress(25, f"Generating synthetic ({synth_params['scenario']}) …")
                all_events = generate_live_synthetic(
                    scenario=synth_params["scenario"],
                    window_minutes=synth_params["window_minutes"],
                    noise_events=synth_params["noise_events"],
                    seed=synth_params["seed"],
                )
                st.session_state.auth_format = "synthetic_live"
                bar.progress(40, f"{len(all_events)} synthetic events")

            elif source_mode == "OSS: flog (CLI)":
                bar.progress(10, "Running flog …")
                try:
                    raw = run_flog(number=flog_params["number"], fmt=flog_params["format"],
                                   use_docker=flog_params["use_docker"])
                except (FlogNotFoundError, FlogRunError) as exc:
                    st.error(str(exc)); st.stop()
                bar.progress(30, "Parsing flog output …")
                flog_ev = parse_flog_output(raw, flog_params["format"])
                if flog_params.get("blend_mvp"):
                    extra = generate_live_synthetic("multi_stage_attack", 60, 4, 42)
                    all_events = flog_ev + extra
                else:
                    all_events = flog_ev
                st.session_state.auth_format = "flog_cli"
                bar.progress(45, f"{len(all_events)} events")

            elif source_mode == "macOS System Logs (last 60m)":
                bar.progress(20, "Fetching macOS logs …")
                conn = MacOSLogsConnector()
                try:
                    all_events = conn.fetch_recent(60, 1800, signal_only=bool(mac_signal_only), keywords=mac_keywords)
                except MacOSLogsConnectorError as exc:
                    st.error(str(exc)); all_events = []
                st.session_state.auth_format = "macos_60m"
                if not all_events:
                    try:
                        gh = GitHubLiveConnector(token=GITHUB_TOKEN, repo=GITHUB_REPO)
                        all_events = gh.fetch_events(limit=150)
                        st.session_state.auth_format = "github_backup"
                    except GitHubLiveConnectorError: pass
                bar.progress(45, f"{len(all_events)} events")

            elif source_mode == "macOS Live Logs (short stream)":
                bar.progress(20, "Capturing live macOS logs …")
                conn = MacOSLogsConnector()
                try:
                    all_events = conn.fetch_live_window(12, 1400, signal_only=bool(mac_signal_only), keywords=mac_keywords)
                except MacOSLogsConnectorError as exc:
                    st.error(str(exc)); all_events = []
                st.session_state.auth_format = "macos_live"
                if not all_events:
                    try:
                        gh = GitHubLiveConnector(token=GITHUB_TOKEN, repo=GITHUB_REPO)
                        all_events = gh.fetch_events(limit=150)
                        st.session_state.auth_format = "github_backup"
                    except GitHubLiveConnectorError: pass
                bar.progress(45, f"{len(all_events)} events")

            elif source_mode == "macOS Live Logs (continuous)":
                conn = MacOSLogsConnector(); all_events = []
                for i in range(int(live_iterations)):
                    bar.progress(10 + int(i / max(int(live_iterations), 1) * 35), f"Capture iter {i+1} …")
                    try:
                        batch = conn.fetch_live_window(int(live_poll_seconds), 500,
                                                       signal_only=bool(mac_signal_only), keywords=mac_keywords)
                    except MacOSLogsConnectorError as exc:
                        st.error(str(exc)); st.stop()
                    all_events.extend(batch)
                    if i < int(live_iterations) - 1: time.sleep(0.2)
                st.session_state.auth_format = "macos_live_continuous"
                if not all_events:
                    try:
                        gh = GitHubLiveConnector(token=GITHUB_TOKEN, repo=GITHUB_REPO)
                        all_events = gh.fetch_events(limit=150)
                        st.session_state.auth_format = "github_backup"
                    except GitHubLiveConnectorError: pass
                bar.progress(45, f"{len(all_events)} events")

            elif source_mode == "GitHub Raw Feed (poll)":
                if not gh_raw_url.strip(): st.error("Provide feed URL."); st.stop()
                conn = GitHubRawFeedConnector(); all_events = []
                for i in range(int(gh_raw_iters)):
                    bar.progress(15 + int(i / max(int(gh_raw_iters), 1) * 35), f"Polling {i+1}/{int(gh_raw_iters)} …")
                    try:
                        batch = conn.fetch(raw_url=gh_raw_url, fmt=gh_raw_fmt, limit=500)
                    except GitHubRawFeedConnectorError as exc:
                        st.error(str(exc)); st.stop()
                    all_events.extend(batch)
                    if i < int(gh_raw_iters) - 1: time.sleep(0.5)
                st.session_state.auth_format = f"github_raw_{gh_raw_fmt}"
                bar.progress(45, f"{len(all_events)} events")

            elif source_mode == "Local Apache/Nginx Access Log":
                if not local_access_path.strip(): st.error("Provide log path."); st.stop()
                all_events = []
                for i in range(int(local_poll_iterations)):
                    bar.progress(15 + int(i / max(int(local_poll_iterations), 1) * 35), f"Reading log {i+1} …")
                    try:
                        with open(local_access_path, "r", encoding="utf-8", errors="ignore") as f:
                            lines = f.readlines()[-int(local_tail_lines):]
                    except Exception as exc:
                        st.error(f"Read failed: {exc}"); st.stop()
                    batch = parse_apache_lines("".join(lines), format_hint="apache_access_live")
                    all_events.extend(batch)
                    if i < int(local_poll_iterations) - 1: time.sleep(1.0)
                st.session_state.auth_format = "local_apache_nginx"
                bar.progress(45, f"{len(all_events)} events")

            st.session_state.events = all_events

            bar.progress(60, "Running detection engine …")
            dets = run_all_detections(all_events, mode="agentic")
            st.session_state.detections = dets
            rules_fb = bool(dets and all((d.metadata or {}).get("generator") == "rules_fallback" for d in dets))
            st.session_state.detection_engine = "rules_fallback" if rules_fb else "agentic"
            _trace(f"Detections ({st.session_state.detection_engine}): {len(dets)}")

            bar.progress(80, "Correlating incidents …")
            incs = enrich_all_incidents(correlate_detections(dets))
            st.session_state.incidents = incs
            _trace(f"Incidents: {len(incs)}")

            bar.progress(100, "Pipeline complete ✓")
            st.session_state.pipeline_run = True
            st.session_state.selected_incident_idx = 0 if incs else None
            st.session_state.incident_context = build_incident_context(incs[0]) if incs else None
            st.session_state.report_text = None
            st.session_state.chat_history = []
            _save_pipeline_memory()
            st.rerun()

    if not st.session_state.pipeline_run:
        # ── PRE-RUN SKELETON — 3-module overview ──────────────────────────────
        sk1, sk2, sk3 = st.columns([5, 4, 5], gap="small")

        # ── MODULE 1: Threat Feed with sparkline SVGs ──
        with sk1:
            _FEED_ITEMS = [
                ("🔴", "Brute-force attempt",  "192.168.1.42",   [2,3,2,5,8,12,9,14,11,16], "#EF4444"),
                ("🟠", "Outbound C2 beacon",   "10.0.0.198",     [1,1,3,2,2,4,5,4,6,7],    "#F97316"),
                ("🔵", "Port scan detected",   "172.16.10.55",   [0,1,0,2,1,3,2,3,4,3],    "#38BDF8"),
                ("🟡", "Privilege escalation", "workstation-07", [1,2,1,2,3,2,4,3,5,6],    "#FACC15"),
                ("🟣", "Lateral movement",     "10.0.0.11",      [0,0,1,1,2,1,3,2,4,5],    "#5EEAD4"),
            ]
            feed_rows = "".join(
                f'<div class="ng-feed-row">'
                f'<div class="ng-feed-icon" style="background:{clr}18;">{icon}</div>'
                f'<div style="flex:1;min-width:0;">'
                f'<div style="font-weight:600;font-size:.78rem;color:#E6FFFA;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">{label}</div>'
                f'<div class="ng-ip">{host}</div>'
                f'</div>'
                f'<div style="flex-shrink:0;opacity:0.85;">{_sparkline_svg(pts, color=clr)}</div>'
                f'</div>'
                for icon, label, host, pts, clr in _FEED_ITEMS
            )
            st.markdown(
                f'<div class="bento-cell" style="height:100%;">'
                f'<div class="ng-skeleton-label">📡 &nbsp;Threat Feed</div>'
                f'{feed_rows}'
                f'<div style="margin-top:12px;font-size:.68rem;color:rgba(100,116,139,0.40);text-align:center;'
                f'font-family:\'JetBrains Mono\',monospace;letter-spacing:.06em;">'
                f'— LIVE DATA AFTER PIPELINE RUN —</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

        # ── MODULE 2: Investigation Status Donut ──
        with sk2:
            _DONUT_SEGS = [
                (4,  "#EF4444", "Critical"),   # neon red
                (9,  "#F97316", "High"),        # vivid orange
                (14, "#FACC15", "Medium"),      # gold
                (7,  "#38BDF8", "Low"),         # electric blue
            ]
            donut_html = _donut_svg(
                _DONUT_SEGS, size=148,
                label_top="?", label_bottom="AWAITING",
            )
            legend_html = "".join(
                f'<div style="display:flex;align-items:center;gap:6px;margin-bottom:5px;">'
                f'<span style="width:9px;height:9px;border-radius:50%;background:{clr};'
                f'box-shadow:0 0 6px {clr}88;flex-shrink:0;"></span>'
                f'<span style="font-size:.72rem;color:rgba(148,163,184,0.80);">{lbl}</span>'
                f'<span style="margin-left:auto;font-size:.72rem;font-weight:700;'
                f'font-family:\'JetBrains Mono\',monospace;color:{clr};">{val}</span>'
                f'</div>'
                for val, clr, lbl in _DONUT_SEGS
            )
            st.markdown(
                f'<div class="bento-cell" style="text-align:center;height:100%;">'
                f'<div class="ng-skeleton-label" style="justify-content:center;">📊 &nbsp;Investigation Status</div>'
                f'<div style="display:flex;justify-content:center;margin-bottom:16px;">{donut_html}</div>'
                f'<div style="text-align:left;padding:0 8px;">{legend_html}</div>'
                f'<div style="margin-top:10px;font-size:.67rem;color:rgba(100,116,139,0.38);'
                f'font-family:\'JetBrains Mono\',monospace;letter-spacing:.05em;">'
                f'SAMPLE DISTRIBUTION</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

        # ── MODULE 3: Asset Overview table ──
        with sk3:
            _ASSETS = [
                ("10.0.0.5",      "dc01.corp",       "critical"),
                ("192.168.1.42",  "workstation-03",  "high"),
                ("10.0.0.198",    "srv-web-01",      "high"),
                ("172.16.10.55",  "guest-net-gw",    "medium"),
                ("10.0.0.11",     "workstation-07",  "medium"),
                ("192.168.1.100", "backup-01",       "low"),
            ]
            _SEV_COLORS = {
                "critical": ("#EF4444", "rgba(239,68,68,0.12)"),
                "high":     ("#F97316", "rgba(249,115,22,0.12)"),
                "medium":   ("#FACC15", "rgba(250,204,21,0.12)"),
                "low":      ("#38BDF8", "rgba(56,189,248,0.12)"),
            }
            rows_html = "".join(
                f'<tr>'
                f'<td><span class="ng-ip">{ip}</span></td>'
                f'<td style="color:rgba(148,163,184,0.80);font-size:.75rem;">{host}</td>'
                f'<td><span class="ng-sev-flag" style="color:{_SEV_COLORS[sev][0]};'
                f'background:{_SEV_COLORS[sev][1]};border:1px solid {_SEV_COLORS[sev][0]}40;">'
                f'{sev}</span></td>'
                f'</tr>'
                for ip, host, sev in _ASSETS
            )
            st.markdown(
                f'<div class="bento-cell" style="height:100%;">'
                f'<div class="ng-skeleton-label">🖥 &nbsp;Asset Overview</div>'
                f'<table class="ng-asset-table">'
                f'<thead><tr><th>IP Address</th><th>Hostname</th><th>Severity</th></tr></thead>'
                f'<tbody>{rows_html}</tbody>'
                f'</table>'
                f'<div style="margin-top:12px;font-size:.68rem;color:rgba(100,116,139,0.40);text-align:center;'
                f'font-family:\'JetBrains Mono\',monospace;letter-spacing:.06em;">'
                f'— DEMO DATA — RUN PIPELINE TO POPULATE —</div>'
                f'</div>',
                unsafe_allow_html=True,
            )
    else:
        # ── STAT CARDS — Bento row of 4 ──────────────────────
        ev_cnt  = len(st.session_state.events)
        det_cnt = len(st.session_state.detections)
        inc_cnt = len(st.session_state.incidents)
        hi_cnt  = sum(1 for i in st.session_state.incidents if i.severity in ("high", "critical"))

        sm1, sm2, sm3, sm4 = st.columns(4, gap="small")
        sm1.metric("Events Ingested",   f"{ev_cnt:,}")
        sm2.metric("Open Detections",   det_cnt)
        sm3.metric("Active Incidents",  inc_cnt)
        sm4.metric("Critical / High",   hi_cnt)

        st.markdown("<div style='height:10px;'></div>", unsafe_allow_html=True)

        # ── CHARTS — Bento row 1: Trend + Severity ────────────
        import pandas as pd

        all_ev = st.session_state.events
        df_ev  = pd.DataFrame([{
            "ts": e.timestamp, "type": e.event_type, "sev": e.severity, "src": e.log_source,
        } for e in all_ev if e.timestamp])

        ch1, ch2 = st.columns([3, 2], gap="small")
        with ch1:
            st.markdown('<div class="bento-cell">', unsafe_allow_html=True)
            _section("", "DETECTION TREND")
            if not df_ev.empty:
                ts_s  = pd.to_datetime(df_ev["ts"], errors="coerce").dropna()
                trend = pd.Series(1, index=ts_s).groupby(pd.Grouper(freq="h")).sum()
                st.area_chart(trend, color="#5EEAD4", height=180)
            else:
                st.caption("No event data.")
            st.markdown('</div>', unsafe_allow_html=True)

        with ch2:
            st.markdown('<div class="bento-cell">', unsafe_allow_html=True)
            _section("", "SEVERITY DISTRIBUTION")
            if st.session_state.detections:
                sev_counts = {}
                for d in st.session_state.detections:
                    sev_counts[d.severity] = sev_counts.get(d.severity, 0) + 1
                sev_df = pd.DataFrame(list(sev_counts.items()), columns=["Severity", "Count"])
                sev_df = sev_df.sort_values("Count", ascending=False)
                st.bar_chart(sev_df.set_index("Severity"), height=180)
            else:
                st.caption("No detections yet.")
            st.markdown('</div>', unsafe_allow_html=True)

        st.markdown("<div style='height:10px;'></div>", unsafe_allow_html=True)

        # ── CHARTS — Bento row 2: Attack categories + MITRE ───
        ch3, ch4 = st.columns([2, 3], gap="small")
        with ch3:
            st.markdown('<div class="bento-cell">', unsafe_allow_html=True)
            _section("", "ATTACK CATEGORIES")
            if not df_ev.empty:
                st.bar_chart(df_ev["type"].value_counts().head(8).rename("Events"), height=160)
            else:
                st.caption("No event data.")
            st.markdown('</div>', unsafe_allow_html=True)

        with ch4:
            st.markdown('<div class="bento-cell">', unsafe_allow_html=True)
            _section("", "MITRE TECHNIQUES")
            all_techniques: list[str] = []
            for inc in st.session_state.incidents:
                all_techniques.extend(inc.mitre_techniques)
            if all_techniques:
                tdf = pd.Series(all_techniques).value_counts().head(8)
                st.bar_chart(tdf, height=160)
            else:
                st.caption("No MITRE data.")
            st.markdown('</div>', unsafe_allow_html=True)

        st.markdown("<div style='height:10px;'></div>", unsafe_allow_html=True)

        # ── BOTTOM BENTO ROW: Recent incidents + Risky entities ──
        bot1, bot2 = st.columns([3, 2], gap="small")

        with bot1:
            st.markdown('<div class="bento-cell">', unsafe_allow_html=True)
            # ── RECENT CRITICAL INCIDENTS ─────────────────────────
            _section("", "RECENT HIGH-RISK INCIDENTS")
            hi_incs = [i for i in st.session_state.incidents if i.severity in ("critical","high")]
            if hi_incs:
                for inc in hi_incs[:6]:
                    c = _sc(inc.severity)
                    cs = inc.criticality_score
                    with st.container():
                        r1, r2, r3, r4, r5 = st.columns([3, 1, 1, 1, 1])
                        r1.markdown(
                            f'{_badge(inc.severity)} <span style="font-weight:600;color:#E6FFFA;font-size:.84rem;margin-left:6px;">{inc.title}</span>',
                            unsafe_allow_html=True,
                        )
                        r2.markdown(f'<span style="color:#A7F3D0;font-size:.78rem;">{inc.affected_user or "—"}</span>', unsafe_allow_html=True)
                        r3.markdown(f'<span style="color:{c};font-weight:700;font-size:.88rem;">{cs:.0f}</span>', unsafe_allow_html=True)
                        r4.markdown(f'<span style="color:rgba(100,116,139,0.70);font-size:.75rem;font-family:monospace;">{str(inc.first_seen)[:16] if inc.first_seen else "—"}</span>', unsafe_allow_html=True)
                        if r5.button("Open", key=f"dash_open_{inc.incident_id}"):
                            idx = st.session_state.incidents.index(inc)
                            st.session_state.selected_incident_idx = idx
                            st.session_state.incident_context = build_incident_context(inc)
                            st.session_state.page = "Incidents"
                            st.rerun()
                    st.markdown("<hr style='margin:4px 0;border-color:rgba(255,255,255,0.06);'>", unsafe_allow_html=True)
            else:
                st.markdown('<div style="color:rgba(100,116,139,0.70);font-size:.84rem;">No high-risk incidents found.</div>', unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

        with bot2:
            st.markdown('<div class="bento-cell">', unsafe_allow_html=True)
            # ── TOP RISKY ENTITIES ────────────────────────────────
            _section("", "TOP RISKY ENTITIES")
            entity_risk: dict[str, float] = {}
            for d in st.session_state.detections:
                for ent in [d.src_ip, d.user, d.host]:
                    if ent:
                        entity_risk[ent] = max(entity_risk.get(ent, 0.0), d.risk_score)
            if entity_risk:
                top_ents = sorted(entity_risk.items(), key=lambda x: -x[1])[:8]
                for ent, score in top_ents:
                    w = int(score)
                    clr = "#EF4444" if score >= 75 else "#F97316" if score >= 55 else "#FACC15"
                    st.markdown(
                        f'<div class="ng-stat-row">'
                        f'<span style="font-family:monospace;font-size:.8rem;color:#A7F3D0;">{ent}</span>'
                        f'<div style="display:flex;align-items:center;gap:8px;">'
                        f'<div style="width:80px;height:5px;background:rgba(255,255,255,0.07);border-radius:3px;overflow:hidden;">'
                        f'<div style="width:{w}%;height:100%;background:{clr};border-radius:3px;"></div></div>'
                        f'<span style="color:{clr};font-weight:700;font-size:.8rem;min-width:28px;">{score:.0f}</span>'
                        f'</div></div>',
                        unsafe_allow_html=True,
                    )
            else:
                st.caption("No entity data.")
            st.markdown('</div>', unsafe_allow_html=True)

        # ── PIPELINE TRACE ────────────────────────────────────
        with st.expander("Pipeline trace", expanded=False):
            for i, line in enumerate(st.session_state.pipeline_trace, 1):
                st.caption(f"`{i:02d}` {line}")


# ─────────────────────────────────────────────────────────────
# PAGE: DETECTIONS
# ─────────────────────────────────────────────────────────────
elif page == "Detections":
    if not st.session_state.pipeline_run:
        st.info("Run the analysis pipeline from the **Dashboard** first.")
    elif not st.session_state.detections:
        status = get_last_agentic_status()
        st.warning(
            f"No detections returned. Engine status: `{status.get('reason','unknown')}`"
            + (f" — {status['detail']}" if status.get("detail") else ""),
            icon="⚠️",
        )
    else:
        dets = st.session_state.detections

        # ── Filters ───────────────────────────────────────────
        f1, f2, f3, f4 = st.columns(4)
        flt_sev    = f1.multiselect("Severity", ["critical","high","medium","low","info"],
                                    default=["critical","high","medium","low","info"],
                                    label_visibility="collapsed")
        flt_status = f2.multiselect("Status", ["New","Investigating","Closed","Escalated"],
                                    default=["New","Investigating"],
                                    label_visibility="collapsed")
        flt_search = f3.text_input("Search", placeholder="Name, IP, user …",
                                   label_visibility="collapsed")
        f4.caption(f"{len(dets)} total detections")

        # ── Quick filter chips ────────────────────────────────
        qc1, qc2, qc3, _ = st.columns([1, 1, 1, 4])
        if qc1.button("Critical Only"):
            flt_sev    = ["critical"]
            flt_status = ["New", "Investigating"]
        if qc2.button("Investigating"):
            flt_status = ["Investigating"]
        if qc3.button("Reset"):
            flt_sev    = ["critical","high","medium","low","info"]
            flt_status = ["New","Investigating","Closed","Escalated"]

        # ── Filter logic ──────────────────────────────────────
        visible = [
            d for d in dets
            if d.severity.lower() in [s.lower() for s in flt_sev]
            and st.session_state.alert_status.get(d.detection_id, "New") in flt_status
            and (not flt_search or flt_search.lower() in f"{d.detection_name} {d.src_ip} {d.user} {d.host}".lower())
        ]

        # ── Split: table | detail ─────────────────────────────
        tbl_col, det_col = st.columns([3, 2], gap="large")

        with tbl_col:
            st.caption(f"{len(visible)} alerts matched")
            st.markdown("<div style='height:6px;'></div>", unsafe_allow_html=True)
            for d in visible:
                c  = _sc(d.severity)
                st_label = st.session_state.alert_status.get(d.detection_id, "New")
                with st.container():
                    row1, row2, row3, row4 = st.columns([4, 1, 1, 1])
                    with row1:
                        st.markdown(
                            f'{_badge(d.severity)} '
                            f'<span style="font-weight:600;color:#E6FFFA;font-size:.84rem;margin-left:6px;">{d.detection_name}</span> '
                            f'<span style="font-size:.72rem;color:rgba(100,116,139,0.55);font-family:monospace;">{d.detection_id}</span>',
                            unsafe_allow_html=True,
                        )
                    with row2:
                        st.markdown(
                            f'<span style="color:{c};font-weight:700;">{d.risk_score:.0f}</span>'
                            f'<span style="color:rgba(100,116,139,0.65);font-size:.72rem;"> risk</span>',
                            unsafe_allow_html=True,
                        )
                    with row3:
                        st.markdown(_status_badge(st_label), unsafe_allow_html=True)
                    with row4:
                        if st.button("→", key=f"sel_{d.detection_id}", help="Open detail"):
                            st.session_state["_selected_det"] = d.detection_id

                    # Compact entity row
                    ents = " ".join([
                        _entity_pill("IP", d.src_ip or "") if d.src_ip else "",
                        _entity_pill("USER", d.user or "", "#5EEAD4") if d.user else "",
                        _entity_pill("HOST", d.host or "", "#34d399") if d.host else "",
                    ])
                    ts = f"{str(d.first_seen)[11:19]} → {str(d.last_seen)[11:19]}" if d.first_seen else "—"
                    st.markdown(
                        f'<div style="padding:3px 0 8px;font-size:.75rem;color:rgba(100,116,139,0.65);">'
                        f'{ents}&nbsp;<span style="font-family:monospace;">{ts}</span></div>',
                        unsafe_allow_html=True,
                    )
                st.markdown("<div style='height:1px;background:rgba(255,255,255,0.07);margin:0 0 6px;'></div>",
                            unsafe_allow_html=True)

        # ── Detail panel ──────────────────────────────────────
        with det_col:
            sel_id = st.session_state.get("_selected_det") or (visible[0].detection_id if visible else None)
            sel_d  = next((d for d in dets if d.detection_id == sel_id), None)

            if sel_d:
                c = _sc(sel_d.severity)
                st.markdown(
                    f'<div class="ng-card">'
                    f'<div style="font-size:1rem;font-weight:700;color:#E6FFFA;margin-bottom:8px;">{sel_d.detection_name}</div>'
                    f'{_badge(sel_d.severity, "lg")} '
                    f'<span style="color:{c};font-size:1.3rem;font-weight:800;margin-left:8px;">{sel_d.risk_score:.0f}</span>'
                    f'<span style="color:#6EE7B7;font-size:.72rem;"> / 100 risk</span>'
                    f'<div style="margin-top:10px;color:#A7F3D0;font-size:.82rem;">{sel_d.description}</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

                # Quick actions
                _section("", "ACTIONS")
                qa1, qa2, qa3, qa4 = st.columns(4)
                if qa1.button("Investigate", key="qa_inv"):
                    st.session_state.alert_status[sel_d.detection_id] = "Investigating"
                if qa2.button("Close", key="qa_close"):
                    st.session_state.alert_status[sel_d.detection_id] = "Closed"
                if qa3.button("Escalate", key="qa_esc"):
                    st.session_state.alert_status[sel_d.detection_id] = "Escalated"
                if qa4.button("→ Incident", key="qa_inc"):
                    st.session_state.page = "Incidents"
                    st.rerun()

                # Entity context
                _section("", "ENTITIES")
                ents_html = " ".join(filter(None, [
                    _entity_pill("SRC IP", sel_d.src_ip or ""),
                    _entity_pill("DST IP", sel_d.dst_ip or "", "#F97316"),
                    _entity_pill("USER", sel_d.user or "", "#5EEAD4"),
                    _entity_pill("HOST", sel_d.host or "", "#34d399"),
                ]))
                st.markdown(ents_html or '<span style="color:rgba(100,116,139,0.65);">No entities.</span>',
                            unsafe_allow_html=True)

                # Timeline of events in detection
                _section("", "RELATED EVENTS")
                for ev in sel_d.events[:8]:
                    ec = ET_CLR.get(ev.event_type, "#6EE7B7")
                    st.markdown(
                        f'<div class="ng-timeline-row">'
                        f'<span class="ng-timeline-dot" style="background:{ec};"></span>'
                        f'<div style="flex:1;">'
                        f'<span style="font-size:.7rem;color:{ec};font-weight:600;text-transform:uppercase;">{_etl(ev.event_type)}</span>'
                        f'<span style="font-size:.72rem;color:rgba(100,116,139,0.65);font-family:monospace;margin-left:8px;">{str(ev.timestamp)[11:19] if ev.timestamp else "—"}</span>'
                        f'<div style="font-size:.78rem;color:#A7F3D0;margin-top:2px;">{ev.raw_log[:90]}…</div>'
                        f'</div></div>',
                        unsafe_allow_html=True,
                    )

                # Tags
                if sel_d.tags:
                    _section("", "TAGS")
                    tags_html = " ".join(
                        f'<span style="display:inline-block;padding:2px 8px;border-radius:5px;font-size:.7rem;'
                        f'background:rgba(94,234,212,.08);color:#5EEAD4;border:1px solid rgba(94,234,212,.15);">{t}</span>'
                        for t in sel_d.tags
                    )
                    st.markdown(tags_html, unsafe_allow_html=True)

                # Notes
                _section("", "ANALYST NOTES")
                note = st.text_area("Notes", value=st.session_state.alert_notes.get(sel_d.detection_id, ""),
                                    key=f"note_{sel_d.detection_id}", height=80, label_visibility="collapsed",
                                    placeholder="Add investigation notes …")
                st.session_state.alert_notes[sel_d.detection_id] = note
            else:
                st.markdown('<div class="ng-card" style="color:rgba(100,116,139,0.65);text-align:center;padding:40px;">Select a detection from the left.</div>',
                            unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
# PAGE: INCIDENTS (3-column workspace)
# ─────────────────────────────────────────────────────────────
elif page == "Incidents":
    if not st.session_state.pipeline_run:
        st.info("Run the analysis pipeline from the **Dashboard** first.")
    elif not st.session_state.incidents:
        st.warning("No incidents correlated. Check detection results.")
    else:
        incidents = st.session_state.incidents
        # Incident picker
        pick_col, _ = st.columns([3, 5])
        with pick_col:
            idx = st.selectbox(
                "Active incident",
                range(len(incidents)),
                format_func=lambda i: f"{incidents[i].incident_id} — {incidents[i].title}",
                index=st.session_state.selected_incident_idx or 0,
                label_visibility="visible",
                key="inc_picker",
            )
        st.session_state.selected_incident_idx = idx
        inc = incidents[idx]
        if not inc.mitre_tactics and not inc.mitre_techniques:
            inc.mitre_tactics, inc.mitre_techniques = map_to_mitre(inc)
        ctx = build_incident_context(inc)
        st.session_state.incident_context = ctx
        c   = _sc(inc.severity)

        # ── 3-COLUMN LAYOUT ───────────────────────────────────
        rail_col, center_col, right_col = st.columns([2, 5, 2], gap="small")

        # ── LEFT RAIL — Summary ───────────────────────────────
        with rail_col:
            st.markdown(
                f'<div class="ng-workspace-rail">'
                f'<div style="font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:rgba(100,116,139,0.65);margin-bottom:10px;">INCIDENT</div>'
                f'<div style="font-size:.9rem;font-weight:700;color:#E6FFFA;margin-bottom:8px;line-height:1.4;">{inc.title}</div>'
                f'<div style="margin-bottom:10px;">{_badge(inc.severity, "lg")}</div>'
                f'<div style="display:flex;align-items:baseline;gap:6px;margin-bottom:10px;">'
                f'<span style="font-size:2.4rem;font-weight:800;color:{c};">{inc.criticality_score:.0f}</span>'
                f'<div><div style="font-size:.62rem;color:#6EE7B7;text-transform:uppercase;">Criticality</div>'
                f'<div style="font-size:.75rem;color:#6EE7B7;">Conf: <b style="color:#A7F3D0">{inc.confidence:.0%}</b></div>'
                f'</div></div>',
                unsafe_allow_html=True,
            )

            # Entities
            for icon, lbl, val, clr in [
                ("👤", "User",   inc.affected_user,   "#5EEAD4"),
                ("🖥", "Host",   inc.affected_host,   "#34d399"),
                ("📡", "Src IP", inc.primary_src_ip,  "#5EEAD4"),
                ("🎯", "Dst IP", inc.primary_dst_ip,  "#F97316"),
            ]:
                if val:
                    st.markdown(
                        f'<div style="display:flex;align-items:center;gap:7px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,0.06);">'
                        f'<span style="font-size:.9rem;">{icon}</span>'
                        f'<div><div style="font-size:.63rem;color:rgba(100,116,139,0.65);font-weight:600;text-transform:uppercase;">{lbl}</div>'
                        f'<div style="font-size:.8rem;color:{clr};font-weight:600;word-break:break-all;">{val}</div></div>'
                        f'</div>',
                        unsafe_allow_html=True,
                    )

            st.markdown("<div style='height:14px;'></div>", unsafe_allow_html=True)

            # Quick response actions
            st.markdown('<div style="font-size:.63rem;font-weight:700;color:rgba(100,116,139,0.65);text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px;">RESPONSE</div>',
                        unsafe_allow_html=True)
            if st.button("Mark Investigating", use_container_width=True):
                st.session_state.alert_status[inc.incident_id] = "Investigating"
            if st.button("Escalate", use_container_width=True):
                st.session_state.alert_status[inc.incident_id] = "Escalated"
            if st.button("Close Case", use_container_width=True):
                st.session_state.alert_status[inc.incident_id] = "Closed"

            # Download actions
            st.markdown("<div style='height:10px;'></div>", unsafe_allow_html=True)
            json_data = export_incident_json(inc)
            csv_data  = export_incident_csv(inc)
            st.download_button("⬇ JSON", json_data, f"{inc.incident_id}.json", "application/json",
                               use_container_width=True)
            st.download_button("⬇ CSV", csv_data, f"{inc.incident_id}.csv", "text/csv",
                               use_container_width=True)

            st.markdown("</div>", unsafe_allow_html=True)

        # ── CENTER — Investigation tabs ───────────────────────
        with center_col:
            (t_overview, t_evidence, t_timeline, t_graph,
             t_mitre, t_chat) = st.tabs([
                "Overview", "Evidence", "Timeline", "Graph", "MITRE", "Chat",
            ])

            # ── OVERVIEW ─────────────────────────────────────
            with t_overview:
                st.markdown(
                    f'<div class="ng-card">'
                    f'<div style="font-size:.68rem;font-weight:700;color:rgba(100,116,139,0.65);text-transform:uppercase;margin-bottom:6px;">INCIDENT SUMMARY</div>'
                    f'<div style="color:#A7F3D0;font-size:.88rem;line-height:1.7;">{inc.summary}</div>'
                    f'<div style="margin-top:10px;font-size:.72rem;color:rgba(100,116,139,0.65);font-family:monospace;">'
                    f'{str(inc.first_seen)[:19] if inc.first_seen else "—"}  →  {str(inc.last_seen)[:19] if inc.last_seen else "—"}'
                    f'</div></div>',
                    unsafe_allow_html=True,
                )

                # Top evidence highlights (detections)
                _section("", "DETECTION SUMMARY")
                for d in inc.detections:
                    dc = _sc(d.severity)
                    st.markdown(
                        f'<div style="display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid rgba(255,255,255,0.06);">'
                        f'<span style="width:8px;height:8px;border-radius:50%;background:{dc};flex-shrink:0;"></span>'
                        f'{_badge(d.severity)}'
                        f'<span style="font-weight:600;color:#E6FFFA;font-size:.84rem;flex:1;">{d.detection_name}</span>'
                        f'<span style="color:{dc};font-weight:700;font-size:.82rem;">{d.risk_score:.0f}</span>'
                        f'<span style="color:rgba(100,116,139,0.65);font-size:.75rem;">conf {d.confidence:.0%}</span>'
                        f'</div>',
                        unsafe_allow_html=True,
                    )

                # Top MITRE techniques
                if inc.mitre_techniques:
                    _section("", "KEY MITRE TECHNIQUES")
                    techs_html = " ".join(
                        f'<span class="ng-mitre-pill" style="background:rgba(94,234,212,.08);color:#5EEAD4;border:1px solid rgba(94,234,212,.2);">{t}</span>'
                        for t in inc.mitre_techniques[:6]
                    )
                    st.markdown(techs_html, unsafe_allow_html=True)

                # Next recommended action
                if inc.recommended_actions:
                    _section("", "RECOMMENDED NEXT STEPS")
                    for i, a in enumerate(inc.recommended_actions[:4], 1):
                        st.markdown(
                            f'<div style="display:flex;align-items:flex-start;gap:10px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,0.06);">'
                            f'<span style="min-width:22px;height:22px;border-radius:50%;background:rgba(34,197,94,.08);color:#22C55E;'
                            f'display:inline-flex;align-items:center;justify-content:center;font-size:.72rem;font-weight:700;flex-shrink:0;">{i}</span>'
                            f'<span style="color:#A7F3D0;font-size:.82rem;">{a}</span></div>',
                            unsafe_allow_html=True,
                        )

            # ── EVIDENCE TRIAGE ───────────────────────────────
            with t_evidence:
                st.caption("Evidence-constrained triage: pack → LLM → verifier → deferral decision.")
                if not is_llm_configured():
                    st.warning("No LLM key configured — triage will use rule baseline only.", icon="⚠️")

                run_vanilla = st.checkbox("Run vanilla LLM baseline (extra API call)", False)
                if st.button("▶  Run Evidence Pipeline", type="primary"):
                    with st.spinner("Building evidence pack, running triage …"):
                        result = run_evidence_triage_workflow(
                            inc,
                            run_llm=is_llm_configured(),
                            run_vanilla_baseline=run_vanilla and is_llm_configured(),
                        )
                    st.session_state.evidence_flow_results[inc.incident_id] = result
                    with st.spinner("Summarising final decision ..."):
                        st.session_state[f"decision_summary_{inc.incident_id}"] = _generate_final_decision_summary(inc, result)
                    st.success("Evidence pipeline complete.")

                res = st.session_state.evidence_flow_results.get(inc.incident_id)
                if res:
                    fd  = res.get("final_decision") or {}
                    dec = fd.get("final_decision", "—")
                    dec_clr = {"close": "#22C55E", "escalate": "#EF4444", "defer": "#FACC15"}.get(dec, "#6EE7B7")
                    st.markdown(
                        f'<div class="ng-card" style="border-color:{dec_clr}40;">'
                        f'<div style="font-size:.68rem;color:rgba(100,116,139,0.65);font-weight:700;text-transform:uppercase;margin-bottom:6px;">FINAL DECISION</div>'
                        f'<span style="font-size:1.4rem;font-weight:800;color:{dec_clr};">{dec.upper()}</span>'
                        f'<div style="color:#A7F3D0;font-size:.82rem;margin-top:6px;">{fd.get("reason","")}</div>'
                        f'<div style="color:rgba(100,116,139,0.65);font-size:.72rem;margin-top:4px;">Policy: {fd.get("policy_applied","")}</div>'
                        f'</div>',
                        unsafe_allow_html=True,
                    )
                    st.markdown("**Decision rationale**")
                    st.markdown(
                        st.session_state.get(f"decision_summary_{inc.incident_id}")
                        or _fallback_final_decision_summary(inc, res)
                    )

                    ev_pack = res.get("evidence_pack") or {}
                    triage  = res.get("triage") or {}
                    verif   = res.get("verifier") or {}

                    with st.expander("Evidence Pack", expanded=False):
                        cov = (ev_pack.get("coverage_summary") or {}).get("coverage_score", "—")
                        st.caption(f"Coverage score: {cov}")
                        st.download_button("⬇ Pack JSON", json.dumps(ev_pack, indent=2, default=str),
                                           f"{inc.incident_id}_pack.json", "application/json")
                        st.json(ev_pack)

                    with st.expander("Triage Output (structured JSON)", expanded=True):
                        if res.get("triage_parse_errors"):
                            st.error("Parse errors: " + ", ".join(res["triage_parse_errors"]))
                        # Evidence items as structured cards
                        claims = triage.get("claims") or []
                        for claim in claims:
                            conf = claim.get("confidence", 0)
                            conf_clr = "#22C55E" if conf >= 0.75 else "#FACC15" if conf >= 0.5 else "#EF4444"
                            st.markdown(
                                f'<div class="ng-evidence-card">'
                                f'<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">'
                                f'<span style="font-weight:600;color:#E6FFFA;font-size:.84rem;">{claim.get("claim","")}</span>'
                                f'<span style="color:{conf_clr};font-size:.78rem;font-weight:700;">{conf:.0%} conf</span>'
                                f'</div>'
                                f'<div style="font-size:.78rem;color:#A7F3D0;">{claim.get("reasoning","")}</div>'
                                f'</div>',
                                unsafe_allow_html=True,
                            )
                        if not claims:
                            st.json(triage)

                    with st.expander("Verifier Results", expanded=True):
                        v_valid = verif.get("is_valid", False)
                        vclr    = "#22C55E" if v_valid else "#EF4444"
                        st.markdown(
                            f'<span style="color:{vclr};font-weight:700;">{"VALID" if v_valid else "INVALID"}</span>'
                            f' &nbsp;·&nbsp; Coverage: {verif.get("coverage_assessment","—")}'
                            f' &nbsp;·&nbsp; Confidence: {verif.get("confidence_assessment","—")}',
                            unsafe_allow_html=True,
                        )
                        if verif.get("unsupported_claims"):
                            st.caption("Unsupported claims: " + ", ".join(verif["unsupported_claims"]))
                        if verif.get("contradictions"):
                            st.caption("Contradictions: " + ", ".join(verif["contradictions"]))

                    with st.expander("Baselines", expanded=False):
                        st.json(res.get("baselines") or {})
                else:
                    st.caption("Run the evidence pipeline above to see results.")

            # ── TIMELINE ─────────────────────────────────────
            with t_timeline:
                timeline_items = ctx.get("timeline", [])
                if not timeline_items:
                    st.caption("No timeline data.")
                else:
                    # Type filter
                    all_types = list({e.get("event_type","") for e in timeline_items})
                    flt_types = st.multiselect("Filter event types", all_types, default=all_types,
                                               label_visibility="collapsed")
                    for entry in timeline_items:
                        et = entry.get("event_type", "")
                        if et not in flt_types:
                            continue
                        ec = ET_CLR.get(et, "#6EE7B7")
                        st.markdown(
                            f'<div class="ng-timeline-row">'
                            f'<span style="min-width:140px;font-family:monospace;font-size:.74rem;color:rgba(100,116,139,0.65);">{entry.get("timestamp","")}</span>'
                            f'<span class="ng-timeline-dot" style="background:{ec};margin-top:5px;"></span>'
                            f'<div style="flex:1;">'
                            f'<span style="font-size:.7rem;font-weight:700;text-transform:uppercase;color:{ec};">{_etl(et)}</span>'
                            f'<div style="font-size:.8rem;color:#A7F3D0;margin-top:2px;">{entry.get("description","")}</div>'
                            f'</div></div>',
                            unsafe_allow_html=True,
                        )

            # ── GRAPH ─────────────────────────────────────────
            with t_graph:
                kg_data = inc.metadata.get("knowledge_graph") or {}
                neo_ready = neo4j_graph.neo4j_configured()

                # Header: buttons row
                btn1, btn2, btn3 = st.columns(3)
                with btn1:
                    st.link_button("Open Neo4j Browser", neo4j_graph.browser_url(), use_container_width=True)
                with btn2:
                    sync_clicked = st.button("Sync selected incident", disabled=not neo_ready, use_container_width=True, key="tg_sync")
                with btn3:
                    fetch_clicked = st.button("Fetch from Neo4j", disabled=not neo_ready, use_container_width=True, key="tg_fetch")

                # Handle sync: push then fetch back
                if sync_clicked:
                    ok, msg = neo4j_graph.sync_incident_knowledge_graph(inc.incident_id, kg_data)
                    if ok:
                        from connectors.neo4j_graph import fetch_incident_knowledge_graph
                        ok2, fetched, msg2 = fetch_incident_knowledge_graph(inc.incident_id)
                        if ok2:
                            st.session_state[f"kg_fetched_{inc.incident_id}"] = fetched
                        st.session_state[f"kg_status_{inc.incident_id}"] = f"{msg} {msg2 if ok2 else ''}".strip()
                    else:
                        st.session_state[f"kg_status_{inc.incident_id}"] = msg

                # Handle fetch
                if fetch_clicked:
                    from connectors.neo4j_graph import fetch_incident_knowledge_graph
                    ok, fetched, msg = fetch_incident_knowledge_graph(inc.incident_id)
                    if ok:
                        st.session_state[f"kg_fetched_{inc.incident_id}"] = fetched
                    st.session_state[f"kg_status_{inc.incident_id}"] = msg

                # Status line
                status_text = st.session_state.get(
                    f"kg_status_{inc.incident_id}",
                    f"Neo4j connected: {NEO4J_USER} @ {NEO4J_URI}" if neo_ready else "Neo4j not configured. Local graph rendering is still available.",
                )
                st.caption(status_text)

                # Description
                st.markdown(
                    "The knowledge graph stores incident entities and relationships in Neo4j as the project memory layer. "
                    "Instead of embedding raw logs into a vector database, the system uses graph relationships for investigation context."
                )

                # Use fetched graph if available, otherwise local
                render_kg = st.session_state.get(f"kg_fetched_{inc.incident_id}") or kg_data
                if st.session_state.get(f"kg_fetched_{inc.incident_id}"):
                    st.caption("Rendering graph fetched from Neo4j after sync.")
                else:
                    st.caption("Rendering local incident graph. Sync to Neo4j to store and fetch it from the graph database.")

                # Graph (left) + Cypher (right)
                g_col, c_col = st.columns([1.5, 1])
                with g_col:
                    _render_knowledge_graph(render_kg)
                with c_col:
                    st.markdown("**Cypher**")
                    st.code(neo4j_graph.cypher_subgraph_query(inc.incident_id), language="cypher")

            # ── MITRE ─────────────────────────────────────────
            with t_mitre:
                if not inc.mitre_tactics and not inc.mitre_techniques:
                    st.caption("No MITRE mapping for this incident.")
                else:
                    _section("", "TACTICS")
                    tac_html = " ".join(
                        f'<span class="ng-mitre-pill" style="background:rgba(94,234,212,.08);color:#5EEAD4;border:1px solid rgba(94,234,212,.2);">{t}</span>'
                        for t in inc.mitre_tactics
                    )
                    st.markdown(tac_html or '<span style="color:rgba(100,116,139,0.65);">None.</span>', unsafe_allow_html=True)

                    _section("", "TECHNIQUE CONTEXT")
                    for technique in inc.mitre_techniques:
                        tid = _mitre_id(technique)
                        name = technique.split(" - ", 1)[1] if " - " in technique else technique
                        meta = MITRE_CONTEXT.get(tid, {})
                        link = meta.get("link", f"https://attack.mitre.org/techniques/{tid}/") if tid.startswith("T") else ""
                        evidence = _mitre_detection_evidence(inc, tid)
                        link_html = (
                            f'<a href="{link}" target="_blank" style="color:#67e8f9;font-size:.78rem;text-decoration:none;">MITRE ↗</a>'
                            if link else ""
                        )
                        st.markdown(
                            f'<div class="ng-card">'
                            f'<div style="display:flex;align-items:flex-start;justify-content:space-between;gap:16px;">'
                            f'<div>'
                            f'<div style="font-size:.72rem;color:#5EEAD4;font-weight:800;letter-spacing:.08em;">{tid}</div>'
                            f'<div style="font-size:1rem;color:#E6FFFA;font-weight:800;margin-top:2px;">{name}</div>'
                            f'</div>{link_html}</div>'
                            f'<div style="margin-top:10px;font-size:.8rem;color:#A7F3D0;line-height:1.6;">'
                            f'<b style="color:#A7F3D0;">Stage:</b> {meta.get("stage", "Mapped attack behavior")}<br>'
                            f'<b style="color:#A7F3D0;">Why it applies:</b> {meta.get("why", "This technique is mapped from the correlated detection behavior.")}<br>'
                            f'<b style="color:#A7F3D0;">Evidence:</b> {evidence}'
                            f'</div></div>',
                            unsafe_allow_html=True,
                        )

                    _section("", "AI MITRE ANALYSIS")
                    if not is_llm_configured():
                        st.caption("Configure GROQ_API_KEY or OPENAI_API_KEY to generate an LLM explanation for this MITRE mapping.")
                    else:
                        if st.button("Generate MITRE Context", type="primary", key=f"mitre_ai_{inc.incident_id}"):
                            with st.spinner("Generating MITRE analyst context ..."):
                                st.session_state[f"mitre_ai_ctx_{inc.incident_id}"] = _generate_mitre_llm_context(inc)
                        ai_ctx = st.session_state.get(f"mitre_ai_ctx_{inc.incident_id}")
                        if ai_ctx:
                            st.markdown(ai_ctx)
                        else:
                            st.caption("Click the button to generate stage-by-stage MITRE context with evidence and next steps.")

            # ── CHAT ─────────────────────────────────────────
            with t_chat:
                if not is_llm_configured():
                    st.warning("Configure GROQ_API_KEY or OPENAI_API_KEY to enable the AI assistant.", icon="⚠️")
                else:
                    # Prompt chips
                    chips = ["Summarise this incident", "Why is this high risk?",
                             "What evidence supports this?", "What should I investigate next?",
                             "Which entities matter most?"]
                    chip_cols = st.columns(len(chips))
                    for ci, chip in enumerate(chips):
                        if chip_cols[ci].button(chip, key=f"chip_{ci}"):
                            with st.spinner("Analysing ..."):
                                _submit_incident_chat(chip)

                    for msg in st.session_state.chat_history:
                        with st.chat_message(msg["role"]):
                            st.markdown(msg["content"])

                    if prompt := st.chat_input("Ask about this incident …"):
                        with st.chat_message("user"):
                            st.markdown(prompt)
                        with st.chat_message("assistant"):
                            with st.spinner("Analysing ..."):
                                _submit_incident_chat(prompt)
                            st.markdown(st.session_state.chat_history[-1]["content"])

        # ── RIGHT COLUMN — Context drawer ─────────────────────
        with right_col:
            st.markdown('<div class="ng-workspace-right">', unsafe_allow_html=True)

            st.markdown(
                '<div style="font-size:.63rem;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:rgba(100,116,139,0.65);margin-bottom:10px;">THREAT INTEL</div>',
                unsafe_allow_html=True,
            )
            intel = inc.metadata.get("enrichment_intel") or {}
            if intel.get("ips"):
                for ip, entry in list(intel["ips"].items())[:4]:
                    vt = entry.get("virustotal") or {}
                    ab = entry.get("abuseipdb") or {}
                    mal = (vt.get("last_analysis_stats") or {}).get("malicious", 0)
                    asc = ab.get("abuse_confidence_score", "—")
                    clr = "#EF4444" if (isinstance(mal, int) and mal > 0) else "#22C55E"
                    st.markdown(
                        f'<div style="padding:7px 0;border-bottom:1px solid rgba(255,255,255,0.06);">'
                        f'<div style="font-family:monospace;font-size:.78rem;color:#5EEAD4;">{ip}</div>'
                        f'<div style="font-size:.72rem;color:#6EE7B7;margin-top:2px;">'
                        f'VT: <span style="color:{clr};">{mal} malicious</span> · Abuse: {asc}'
                        f'</div></div>',
                        unsafe_allow_html=True,
                    )
                if intel.get("queried_at_utc"):
                    st.caption(f"Queried: {intel['queried_at_utc']}")
            elif inc.enrichment_links:
                for lbl, url in list(inc.enrichment_links.items())[:4]:
                    st.markdown(
                        f'<a href="{url}" target="_blank" style="display:block;padding:5px 0;'
                        f'color:#5EEAD4;font-size:.78rem;text-decoration:none;border-bottom:1px solid rgba(255,255,255,0.06);">'
                        f'{lbl} ↗</a>',
                        unsafe_allow_html=True,
                    )
            else:
                st.caption("No enrichment data. Add VirusTotal / AbuseIPDB keys.")

            # Related detections
            _section("", "LINKED DETECTIONS")
            for d in inc.detections[:5]:
                st.markdown(
                    f'<div style="padding:5px 0;border-bottom:1px solid rgba(255,255,255,0.06);">'
                    f'{_badge(d.severity)} '
                    f'<span style="font-size:.76rem;color:#A7F3D0;margin-left:4px;">{d.detection_name}</span>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

            # Next steps
            if inc.next_steps:
                _section("", "NEXT STEPS")
                for i, s in enumerate(inc.next_steps[:4], 1):
                    st.markdown(
                        f'<div style="display:flex;gap:7px;padding:5px 0;border-bottom:1px solid rgba(255,255,255,0.06);">'
                        f'<span style="color:#5EEAD4;font-size:.7rem;font-weight:700;flex-shrink:0;">{i}</span>'
                        f'<span style="font-size:.76rem;color:#A7F3D0;">{s}</span>'
                        f'</div>',
                        unsafe_allow_html=True,
                    )

            st.markdown("</div>", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
# PAGE: INVESTIGATIONS (evidence pipeline deep-dive)
# ─────────────────────────────────────────────────────────────
elif page == "Investigations":
    if not st.session_state.pipeline_run or not st.session_state.incidents:
        st.info("Run the analysis pipeline from the **Dashboard** first.")
    else:
        incidents = st.session_state.incidents
        ev_i = st.selectbox(
            "Select incident",
            range(len(incidents)),
            format_func=lambda i: f"{incidents[i].incident_id} — {incidents[i].title}",
            key="inv_inc_sel",
        )
        inc_ev    = incidents[ev_i]
        run_col, opt_col = st.columns([1, 2])
        with opt_col:
            run_vanilla = st.checkbox("Run vanilla LLM baseline", False)
        with run_col:
            run_ev_btn = st.button("▶  Run Evidence Triage Pipeline", type="primary")
        if not is_llm_configured():
            st.warning("No LLM configured — will use rule baseline only.", icon="⚠️")
        if run_ev_btn:
            with st.spinner("Running evidence pack → triage → verifier …"):
                result = run_evidence_triage_workflow(
                    inc_ev,
                    run_llm=is_llm_configured(),
                    run_vanilla_baseline=run_vanilla and is_llm_configured(),
                )
            st.session_state.evidence_flow_results[inc_ev.incident_id] = result
            with st.spinner("Summarising final decision ..."):
                st.session_state[f"decision_summary_{inc_ev.incident_id}"] = _generate_final_decision_summary(inc_ev, result)
            st.success("Evidence pipeline complete.")

        res = st.session_state.evidence_flow_results.get(inc_ev.incident_id)
        if res:
            fd  = res.get("final_decision") or {}
            dec = fd.get("final_decision", "—")
            dec_clr = {"close": "#22C55E", "escalate": "#EF4444", "defer": "#FACC15"}.get(dec, "#6EE7B7")

            fc1, fc2, fc3 = st.columns(3)
            fc1.markdown(
                f'<div class="ng-card" style="border-color:{dec_clr}40;text-align:center;">'
                f'<div style="font-size:.65rem;color:rgba(100,116,139,0.65);text-transform:uppercase;margin-bottom:4px;">Final Decision</div>'
                f'<div style="font-size:1.6rem;font-weight:800;color:{dec_clr};">{dec.upper()}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )
            verif = res.get("verifier") or {}
            v_val = verif.get("is_valid", False)
            fc2.markdown(
                f'<div class="ng-card" style="text-align:center;">'
                f'<div style="font-size:.65rem;color:rgba(100,116,139,0.65);text-transform:uppercase;margin-bottom:4px;">Verifier</div>'
                f'<div style="font-size:1.1rem;font-weight:700;color:{"#22C55E" if v_val else "#EF4444"};">{"VALID" if v_val else "INVALID"}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )
            ep   = res.get("evidence_pack") or {}
            cov  = (ep.get("coverage_summary") or {}).get("coverage_score", "—")
            fc3.markdown(
                f'<div class="ng-card" style="text-align:center;">'
                f'<div style="font-size:.65rem;color:rgba(100,116,139,0.65);text-transform:uppercase;margin-bottom:4px;">Coverage</div>'
                f'<div style="font-size:1.1rem;font-weight:700;color:#A7F3D0;">{cov}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )
            st.markdown("**Decision rationale**")
            st.markdown(
                st.session_state.get(f"decision_summary_{inc_ev.incident_id}")
                or _fallback_final_decision_summary(inc_ev, res)
            )

            with st.expander("Evidence Pack JSON", expanded=False):
                st.download_button("⬇ Download", json.dumps(ep, indent=2, default=str),
                                   f"{inc_ev.incident_id}_pack.json", "application/json", key="dl_ev_pack")
                st.json(ep)

            with st.expander("Triage Agent Output", expanded=True):
                if res.get("triage_parse_errors"):
                    st.error("Parse errors: " + ", ".join(res["triage_parse_errors"]))
                st.json(res.get("triage") or {})
                if res.get("triage_raw"):
                    st.code(res["triage_raw"][:6000], language="text")

            with st.expander("Verifier Detail", expanded=True):
                st.json(verif)

            with st.expander("Baselines & Experiment Log", expanded=False):
                st.markdown("**Rule baseline**")
                st.json((res.get("baselines") or {}).get("rule") or {})
                st.markdown("**Vanilla LLM baseline**")
                vb = (res.get("baselines") or {}).get("vanilla")
                st.json(vb) if vb else st.caption("Not run.")
                st.caption("Each run appends one row to `experiments/logs/triage_runs.jsonl`.")
        else:
            st.caption("Click **Run Evidence Triage Pipeline** above.")


# ─────────────────────────────────────────────────────────────
# PAGE: REPORTS
# ─────────────────────────────────────────────────────────────
elif page == "Reports":
    if not st.session_state.pipeline_run or not st.session_state.incidents:
        st.info("Run the analysis pipeline from the **Dashboard** first.")
    else:
        incidents = st.session_state.incidents

        rp1, rp2 = st.columns([3, 2], gap="large")
        with rp1:
            _section("", "GENERATE REPORT")
            r_idx = st.selectbox(
                "Incident",
                range(len(incidents)),
                format_func=lambda i: incidents[i].title,
                key="rpt_inc_sel",
            )
            r_inc = incidents[r_idx]
            ctx   = build_incident_context(r_inc)
            st.session_state.incident_context = ctx

            sev = ctx.get("severity", "medium")
            st.markdown(
                f'{_badge(sev, "lg")} '
                f'<span style="font-size:.82rem;color:#6EE7B7;">Score: '
                f'<b style="color:#E6FFFA">{ctx.get("criticality_score",0):.0f}/100</b> · '
                f'{ctx.get("incident_id","")}</span>',
                unsafe_allow_html=True,
            )

            r_mode = st.radio("Report type", ["AI-Generated", "Fallback Template"], horizontal=True,
                              key="rpt_type")
            if st.button("✦  Generate Report", type="primary"):
                if r_mode == "AI-Generated":
                    with st.spinner("Generating via LLM …"):
                        rpt = generate_report(ctx)
                    if rpt:
                        st.session_state.report_text = rpt
                        st.session_state.report_mode_ai = True
                    else:
                        st.warning("LLM unavailable — using fallback template.")
                        st.session_state.report_text = build_fallback_report(ctx)
                        st.session_state.report_mode_ai = False
                else:
                    st.session_state.report_text = build_fallback_report(ctx)
                    st.session_state.report_mode_ai = False

            if st.session_state.report_text:
                st.divider()
                if st.session_state.report_mode_ai:
                    with st.container(border=True):
                        st.markdown(st.session_state.report_text)
                else:
                    st.code(st.session_state.report_text, language="text")

        with rp2:
            _section("", "EXPORT OPTIONS")
            if st.session_state.get("incident_context"):
                ctx_inc_id = st.session_state.incident_context.get("incident_id", "")
                exp_inc = next((i for i in incidents if i.incident_id == ctx_inc_id), incidents[0])
                json_d = export_incident_json(exp_inc)
                csv_d  = export_incident_csv(exp_inc)

                with st.container(border=True):
                    st.markdown(
                        f'<div style="text-align:center;padding:14px 0;">'
                        f'<div style="font-size:1.8rem;">📄</div>'
                        f'<div style="font-size:.65rem;text-transform:uppercase;color:#6EE7B7;margin:4px 0;">JSON Export</div>'
                        f'<div style="font-size:1.3rem;font-weight:700;color:#E6FFFA;">{len(json_d):,}</div>'
                        f'<div style="font-size:.72rem;color:rgba(100,116,139,0.65);">bytes · full incident data</div>'
                        f'</div>',
                        unsafe_allow_html=True,
                    )
                    st.download_button("⬇  Download JSON", json_d,
                                       f"{exp_inc.incident_id}.json", "application/json",
                                       use_container_width=True)
                    with st.expander("Preview"):
                        st.json(json.loads(json_d))

                with st.container(border=True):
                    st.markdown(
                        f'<div style="text-align:center;padding:14px 0;">'
                        f'<div style="font-size:1.8rem;">📊</div>'
                        f'<div style="font-size:.65rem;text-transform:uppercase;color:#6EE7B7;margin:4px 0;">CSV Export</div>'
                        f'<div style="font-size:1.3rem;font-weight:700;color:#E6FFFA;">{len(csv_d):,}</div>'
                        f'<div style="font-size:.72rem;color:rgba(100,116,139,0.65);">bytes · flattened summary</div>'
                        f'</div>',
                        unsafe_allow_html=True,
                    )
                    st.download_button("⬇  Download CSV", csv_d,
                                       f"{exp_inc.incident_id}.csv", "text/csv",
                                       use_container_width=True)
                    with st.expander("Preview"):
                        st.code(csv_d, language="text")

            if st.session_state.report_text:
                st.download_button("⬇  Download Report (txt)", st.session_state.report_text,
                                   "report.txt", "text/plain", use_container_width=True)


# ─────────────────────────────────────────────────────────────
# PAGE: ADMIN
# ─────────────────────────────────────────────────────────────
elif page == "Admin":
    def _status_row(label: str, ok: bool, detail: str = "") -> None:
        dot  = "#22C55E" if ok else "#EF4444"
        text = "Healthy" if ok else "Disconnected"
        st.markdown(
            f'<div class="ng-health-row" style="border-bottom:1px solid rgba(255,255,255,0.06);padding:9px 0;">'
            f'<span class="ng-health-dot" style="background:{dot};width:10px;height:10px;"></span>'
            f'<span style="font-weight:600;color:#A7F3D0;min-width:140px;">{label}</span>'
            f'<span style="color:{"#22C55E" if ok else "#EF4444"};font-size:.8rem;font-weight:600;">{text}</span>'
            f'{f"<span style=\"color:rgba(100,116,139,0.65);font-size:.75rem;margin-left:auto;\">{detail}</span>" if detail else ""}'
            f'</div>',
            unsafe_allow_html=True,
        )

    ac1, ac2 = st.columns(2, gap="large")

    with ac1:
        _section("", "CONNECTOR STATUS")
        llm_ok  = is_llm_configured()
        neo_ok  = neo4j_graph.neo4j_configured()
        vt_ok   = bool(VIRUSTOTAL_API_KEY)
        ab_ok   = bool(ABUSEIPDB_API_KEY)
        gh_ok   = bool(GITHUB_TOKEN)

        _status_row("LLM (Groq/OpenAI)", llm_ok,
                    f"{LLM_MODEL} · {LLM_BASE_URL[:30]}…" if llm_ok else "No GROQ_API_KEY set")
        _status_row("Neo4j (Bolt)",      neo_ok,
                    f"{NEO4J_USER}@{NEO4J_URI}" if neo_ok else "NEO4J_URI not set")
        _status_row("VirusTotal",        vt_ok,  "Key configured" if vt_ok else "No VIRUSTOTAL_API_KEY")
        _status_row("AbuseIPDB",         ab_ok,  "Key configured" if ab_ok else "No ABUSEIPDB_API_KEY")
        _status_row("GitHub",            gh_ok,  f"repo: {GITHUB_REPO}" if gh_ok else "No GITHUB_TOKEN")

        _section("", "ENVIRONMENT FILES")
        if ENV_FILES_LOADED:
            for p in ENV_FILES_LOADED:
                st.markdown(
                    f'<div style="font-size:.78rem;color:#6EE7B7;padding:4px 0;border-bottom:1px solid rgba(255,255,255,0.06);">'
                    f'<span style="color:#22C55E;">✓</span>&nbsp;{p}</div>',
                    unsafe_allow_html=True,
                )
        else:
            st.warning("No .env files found. Create `.env` from `.env.example`.")

        _section("", "LLM DETAILS")
        if is_llm_configured():
            hint = ("gsk_…" if LLM_API_KEY.startswith("gsk_")
                    else "sk-…" if LLM_API_KEY.startswith("sk-")
                    else "set")
            st.markdown(
                f'<div style="font-size:.8rem;color:#A7F3D0;padding:8px 0;">'
                f'Source: <b>{LLM_KEY_SOURCE or "env"}</b> · Key: {hint} (len {len(LLM_API_KEY)})<br>'
                f'Model: <b>{LLM_MODEL}</b><br>'
                f'Base URL: <code style="font-size:.75rem;">{LLM_BASE_URL}</code>'
                f'</div>',
                unsafe_allow_html=True,
            )
        else:
            st.caption("Key not configured or is a placeholder. Set `GROQ_API_KEY` in `.env`.")

        # Agentic detector status
        _section("", "AGENTIC DETECTOR STATUS")
        ag_st = get_last_agentic_status()
        ag_ok = ag_st.get("ok", False)
        st.markdown(
            f'<div style="font-size:.8rem;padding:8px 0;color:#A7F3D0;">'
            f'Status: <span style="color:{"#22C55E" if ag_ok else "#EF4444"};font-weight:700;">'
            f'{"OK" if ag_ok else "FAILED"}</span><br>'
            f'Reason: <code>{ag_st.get("reason","not_run")}</code><br>'
            f'{"Detail: " + ag_st["detail"] if ag_st.get("detail") else ""}'
            f'</div>',
            unsafe_allow_html=True,
        )

    with ac2:
        _section("", "SESSION STATISTICS")
        st.markdown(
            f'<div class="ng-card">'
            f'<div class="ng-stat-row"><span>Events ingested</span><span style="color:#E6FFFA;font-weight:700;">{len(st.session_state.events):,}</span></div>'
            f'<div class="ng-stat-row"><span>Detections</span><span style="color:#E6FFFA;font-weight:700;">{len(st.session_state.detections)}</span></div>'
            f'<div class="ng-stat-row"><span>Incidents</span><span style="color:#E6FFFA;font-weight:700;">{len(st.session_state.incidents)}</span></div>'
            f'<div class="ng-stat-row"><span>Detection engine</span>'
            f'<span style="color:#{"22c55e" if st.session_state.detection_engine == "agentic" else "eab308"};font-weight:700;">'
            f'{st.session_state.detection_engine}</span></div>'
            f'<div class="ng-stat-row" style="border:none;"><span>Pipeline run</span>'
            f'<span style="color:#{"22c55e" if st.session_state.pipeline_run else "ef4444"};font-weight:700;">'
            f'{"Yes" if st.session_state.pipeline_run else "No"}</span></div>'
            f'</div>',
            unsafe_allow_html=True,
        )

        _section("", "NEO4J")
        st.markdown(
            f'<div class="ng-card">'
            f'<div class="ng-stat-row"><span>URI</span><span style="font-family:monospace;font-size:.76rem;color:#5EEAD4;">{NEO4J_URI or "—"}</span></div>'
            f'<div class="ng-stat-row"><span>User</span><span style="color:#A7F3D0;">{NEO4J_USER}</span></div>'
            f'<div class="ng-stat-row" style="border:none;"><span>Browser URL</span>'
            f'<a href="{NEO4J_BROWSER_URL}" target="_blank" style="color:#5EEAD4;font-size:.78rem;">Open ↗</a></div>'
            f'</div>',
            unsafe_allow_html=True,
        )

        _section("", "PIPELINE TRACE")
        with st.expander("Last run trace", expanded=False):
            if st.session_state.pipeline_trace:
                for i, line in enumerate(st.session_state.pipeline_trace, 1):
                    st.caption(f"`{i:02d}` {line}")
            else:
                st.caption("No pipeline run yet.")

        if neo4j_graph.neo4j_configured():
            st.link_button("Open Neo4j Browser", neo4j_graph.browser_url(), use_container_width=True)


