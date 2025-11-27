import React, { useEffect, useMemo, useState } from "react";
import axios from "axios";
import {
  PieChart, Pie, Cell, Tooltip as ReTooltip, ResponsiveContainer,
  LineChart, Line, XAxis, YAxis, CartesianGrid, Legend
} from "recharts";
import { FiSearch } from "react-icons/fi";
import "./App.css";

// ✅ العنوان الصحيح للـ API
const API_HOST = process.env.REACT_APP_API_URL || "http://127.0.0.1:5000";
const API_BASE = `${API_HOST}/api`;

const axiosInstance = axios.create({
  baseURL: API_BASE,
  timeout: 7000,
});

const COLORS = ["#4CAF50", "#FF9800", "#2196F3", "#E91E63", "#9C27B0", "#FF5722"];

function formatTimeLabel(ts) {
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return String(ts || "");
    return `${d.getHours()}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
  } catch {
    return ts;
  }
}

export default function App() {
  const [events, setEvents] = useState([]);
  const [blockedThreats, setBlockedThreats] = useState([]);
  const [filter, setFilter] = useState("");
  const [loading, setLoading] = useState(true);
  const [loadingBlocked, setLoadingBlocked] = useState(true);
  const [error, setError] = useState(null);
  const [lastUpdate, setLastUpdate] = useState(null);
  const [urlToCheck, setUrlToCheck] = useState("");
  const [urlCheckResult, setUrlCheckResult] = useState(null);
  const [checkingUrl, setCheckingUrl] = useState(false);
  const [showBlockedUrls, setShowBlockedUrls] = useState(true); // Toggle for Blocked URLs section
  const [blockedUrlsPage, setBlockedUrlsPage] = useState(0); // Current page for blocked URLs pagination
  const [blockedUrlsRowsPerPage, setBlockedUrlsRowsPerPage] = useState(2); // Rows per page (2 initially, 10 when expanded)
  const [eventsDisplayLimit, setEventsDisplayLimit] = useState(20); // Display first 20 rows, then all when clicked

  useEffect(() => {
    let mounted = true;
    let intervalId = null;

    const fetchData = async () => {
      try {
        const res = await axiosInstance.get("/events");
        if (!mounted) return;
        setEvents(res.data || []);
        setError(null);
        setLastUpdate(new Date().toLocaleTimeString());
      } catch (err) {
        console.error("Fetch error:", err);
        if (mounted) {
          if (err.response) {
            setError(`⚠️ Server Error: ${err.response.status} ${err.response.statusText}`);
          } else if (err.request) {
            setError(`⚠️ No response from server — Make sure ${API_BASE} is available.`);
          } else {
            setError(`⚠️ Request Setup Error: ${err.message}`);
          }
        }
      } finally {
        if (mounted) setLoading(false);
      }
    };

    fetchData();
    intervalId = setInterval(fetchData, 3000);

    return () => {
      mounted = false;
      if (intervalId) clearInterval(intervalId);
    };
  }, []);

  // Fetch blocked threats count
  const [blockedThreatsCount, setBlockedThreatsCount] = useState(0);
  const [blockedUrls, setBlockedUrls] = useState([]);
  const [loadingBlockedUrls, setLoadingBlockedUrls] = useState(true);
  const [lastBlockedUrlsUpdate, setLastBlockedUrlsUpdate] = useState(null);
  
  useEffect(() => {
    let mounted = true;
    let intervalId = null;

    const fetchBlockedThreatsCount = async () => {
      try {
        const res = await axiosInstance.get("/blocked-threats-count");
        if (!mounted) return;
        setBlockedThreatsCount(res.data?.count || 0);
      } catch (err) {
        console.error("Fetch blocked threats count error:", err);
        // Fallback to old endpoint
        try {
          const res = await axiosInstance.get("/blocked-threats");
          if (!mounted) return;
          setBlockedThreatsCount(res.data?.length || 0);
        } catch (err2) {
          console.error("Fallback fetch error:", err2);
        }
      } finally {
        if (mounted) setLoadingBlocked(false);
      }
    };

    fetchBlockedThreatsCount();
    intervalId = setInterval(fetchBlockedThreatsCount, 3000);

    return () => {
      mounted = false;
      if (intervalId) clearInterval(intervalId);
    };
  }, []);

  // Fetch blocked URLs
  useEffect(() => {
    let mounted = true;
    let intervalId = null;

    const fetchBlockedUrls = async () => {
      try {
        const res = await axiosInstance.get("/blocked-urls?n=1000");
        if (!mounted) return;
        const data = res.data || [];
        console.log(`[Blocked URLs] Fetched ${data.length} blocked URLs`);
        setBlockedUrls(data);
        setLastBlockedUrlsUpdate(new Date());
      } catch (err) {
        console.error("Fetch blocked URLs error:", err);
        if (mounted) {
          setBlockedUrls([]);
        }
      } finally {
        if (mounted) setLoadingBlockedUrls(false);
      }
    };

    fetchBlockedUrls();
    intervalId = setInterval(fetchBlockedUrls, 2000); // Update every 2 seconds for live detection

    return () => {
      mounted = false;
      if (intervalId) clearInterval(intervalId);
    };
  }, []);

  // ✅ حساب الإحصائيات
  const summary = useMemo(() => {
    const total = events.length;
    const protocols = {};
    const eventTypes = {};
    const timeline = {};

    events.forEach(ev => {
      const proto = (ev.proto || ev.protocol || "UNKNOWN").toString();
      protocols[proto] = (protocols[proto] || 0) + 1;

      const et = (ev.event_type || ev.alert_category || ev.ml_label || "unknown").toString();
      eventTypes[et] = (eventTypes[et] || 0) + 1;

      const tlabel = formatTimeLabel(ev.timestamp || ev.time || ev.ts || "");
      timeline[tlabel] = (timeline[tlabel] || 0) + 1;
    });

    const protoArr = Object.entries(protocols).map(([k, v]) => ({ name: k, value: v }));
    const typesArr = Object.entries(eventTypes).map(([k, v]) => ({ name: k, value: v }));
    const timelineArr = Object.entries(timeline)
      .sort((a, b) => a[0] < b[0] ? -1 : 1)
      .map(([k, v]) => ({ time: k, count: v }));

    return { total, protoArr, typesArr, timelineArr };
  }, [events]);

  const filtered = events.filter(e => {
    if (!filter) return true;
    const s = filter.toLowerCase();
    return JSON.stringify(e).toLowerCase().includes(s);
  });

  // Function to check URL safety
  const checkUrl = async () => {
    if (!urlToCheck.trim()) {
      setUrlCheckResult({ error: "الرجاء إدخال رابط للتحقق" });
      return;
    }

    setCheckingUrl(true);
    setUrlCheckResult(null);
    
    try {
      const response = await axiosInstance.post("/test-url", {
        url: urlToCheck.trim()
      });
      
      const result = response.data;
      setUrlCheckResult({
        url: result.url,
        isSafe: result.is_safe !== undefined ? result.is_safe : (!result.blocked && result.url_validation?.is_valid),
        blocked: result.blocked,
        url_validation: result.url_validation,
        ml_prediction: result.ml_prediction,
        signatures: result.signatures || [],
        ips_decision: result.ips_decision,
        threat_indicators: result.url_validation?.threat_indicators || []
      });
      
      // Refresh blocked threats count if URL was blocked
      if (result.blocked) {
        // Trigger refresh of blocked threats count
        setTimeout(async () => {
          try {
            const res = await axiosInstance.get("/blocked-threats-count");
            setBlockedThreatsCount(res.data?.count || 0);
          } catch (err) {
            console.error("Failed to refresh blocked threats count:", err);
          }
        }, 500);
      }
    } catch (err) {
      console.error("URL check error:", err);
      setUrlCheckResult({
        error: err.response?.data?.error || "An error occurred while checking the URL"
      });
    } finally {
      setCheckingUrl(false);
    }
  };

  return (
    <div className="dashboard-root">
      <header className="dashboard-header">
        <div className="header-left">
          <div className="logo">🛡️</div>
          <div className="title-block">
            <h1>NGFW</h1>
          </div>
        </div>

        <div className="header-right">
          <div style={{ marginRight: 12, color: "#9aa6b2" }}>Last Update: {lastUpdate || "—"}</div>
          <div className="search">
            <FiSearch />
            <input
              placeholder="Search by IP, event type, or protocol..."
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
          </div>
        </div>
      </header>

      <main className="dashboard-main">
        {error && (
          <div style={{ padding: 12, background: "#ffe8e6", color: "#7a1f1f", borderRadius: 8, marginBottom: 12 }}>
            <strong>Error:</strong> {error}
          </div>
        )}

        <section className="cards">
          <div className="card">
            <div className="card-title">Total Events</div>
            <div className="card-value">{loading ? "..." : summary.total}</div>
            <div className="card-sub">From PostgreSQL Database</div>
          </div>

          <div className="card">
            <div className="card-title">Event Types</div>
            <div className="card-value">{summary.typesArr.length}</div>
            <div className="card-sub">Alert Categories</div>
          </div>

          <div className="card">
            <div className="card-title">Filtered</div>
            <div className="card-value">{filtered.length}</div>
            <div className="card-sub">Current Search Results</div>
          </div>

          <div className="card" style={{ background: "rgba(239, 68, 68, 0.1)", border: "1px solid rgba(239, 68, 68, 0.3)" }}>
            <div className="card-title" style={{ color: "#ef4444" }}>Blocked Threats</div>
            <div className="card-value" style={{ color: "#ef4444" }}>{loadingBlocked ? "..." : blockedThreatsCount}</div>
            <div className="card-sub">URLs & Connections Blocked</div>
          </div>
        </section>

        {/* URL Checker Section */}
        <section className="url-checker-section" style={{ marginBottom: 24 }}>
          <div className="card-visual">
            <h3 style={{ marginBottom: 16 }}>🔍 URL Checker</h3>
            <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
              <input
                type="text"
                placeholder="Enter URL to check security..."
                value={urlToCheck}
                onChange={(e) => setUrlToCheck(e.target.value)}
                onKeyPress={(e) => {
                  if (e.key === "Enter") {
                    checkUrl();
                  }
                }}
                style={{
                  flex: 1,
                  padding: "12px 16px",
                  background: "rgba(255, 255, 255, 0.05)",
                  border: "1px solid rgba(255, 255, 255, 0.1)",
                  borderRadius: 8,
                  color: "#e6edf3",
                  fontSize: 14,
                  outline: "none"
                }}
              />
              <button
                onClick={checkUrl}
                disabled={checkingUrl}
                style={{
                  padding: "12px 24px",
                  background: checkingUrl ? "#444" : "linear-gradient(135deg, #58a6ff 0%, #7ee787 100%)",
                  border: "none",
                  borderRadius: 8,
                  color: "#fff",
                  fontSize: 14,
                  fontWeight: 600,
                  cursor: checkingUrl ? "not-allowed" : "pointer",
                  transition: "all 0.3s ease"
                }}
              >
                {checkingUrl ? "Checking..." : "Check URL"}
              </button>
            </div>

            {urlCheckResult && (
              <div
                style={{
                  padding: 16,
                  borderRadius: 12,
                  background: urlCheckResult.error
                    ? "rgba(239, 68, 68, 0.1)"
                    : urlCheckResult.isSafe
                    ? "rgba(34, 197, 94, 0.1)"
                    : "rgba(239, 68, 68, 0.15)",
                  border: `2px solid ${
                    urlCheckResult.error
                      ? "rgba(239, 68, 68, 0.3)"
                      : urlCheckResult.isSafe
                      ? "rgba(34, 197, 94, 0.3)"
                      : "rgba(239, 68, 68, 0.4)"
                  }`
                }}
              >
                {urlCheckResult.error ? (
                  <div style={{ color: "#ef4444" }}>
                    <strong>⚠️ Error:</strong> {urlCheckResult.error}
                  </div>
                ) : (
                  <>
                    <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
                      <span style={{ fontSize: 24 }}>
                        {urlCheckResult.isSafe ? "✅" : "🚫"}
                      </span>
                      <div>
                        <div style={{ fontSize: 16, fontWeight: 600, marginBottom: 4 }}>
                          {urlCheckResult.isSafe ? "URL is Safe" : "URL is Unsafe"}
                        </div>
                        <div style={{ fontSize: 12, color: "#9aa6b2", wordBreak: "break-all" }}>
                          {urlCheckResult.url}
                        </div>
                      </div>
                    </div>

                    {urlCheckResult.threat_indicators && urlCheckResult.threat_indicators.length > 0 && (
                      <div style={{ marginTop: 12, paddingTop: 12, borderTop: "1px solid rgba(255, 255, 255, 0.1)" }}>
                        <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8, color: "#ef4444" }}>
                          ⚠️ Threat Indicators:
                        </div>
                        <ul style={{ margin: 0, paddingLeft: 20, fontSize: 12, color: "#fbbf24" }}>
                          {urlCheckResult.threat_indicators.map((indicator, idx) => (
                            <li key={idx}>{indicator}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {urlCheckResult.signatures && urlCheckResult.signatures.length > 0 && (
                      <div style={{ marginTop: 12, paddingTop: 12, borderTop: "1px solid rgba(255, 255, 255, 0.1)" }}>
                        <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8, color: "#ef4444" }}>
                          🛡️ Matching Signatures:
                        </div>
                        <ul style={{ margin: 0, paddingLeft: 20, fontSize: 12, color: "#fbbf24" }}>
                          {urlCheckResult.signatures.map((sig, idx) => (
                            <li key={idx}>
                              {sig.name} ({sig.severity})
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </>
                )}
              </div>
            )}
          </div>
        </section>

        <section className="vis-grid">
          <div className="chart card-visual">
            <h3>Protocol Distribution</h3>
            {summary.protoArr.length === 0 ? <p>No data</p> :
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie data={summary.protoArr} dataKey="value" nameKey="name" innerRadius={40} outerRadius={80} paddingAngle={4}>
                    {summary.protoArr.map((entry, idx) => (
                      <Cell key={`cell-${idx}`} fill={COLORS[idx % COLORS.length]} />
                    ))}
                  </Pie>
                  <ReTooltip />
                </PieChart>
              </ResponsiveContainer>
            }
          </div>

          <div className="chart card-visual">
            <h3>Events Over Time</h3>
            {summary.timelineArr.length === 0 ? <p>No data</p> :
              <ResponsiveContainer width="100%" height={220}>
                <LineChart data={summary.timelineArr}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="time" />
                  <YAxis 
                    domain={[0, 20]}
                    ticks={[0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20]}
                    allowDecimals={false}
                  />
                  <ReTooltip />
                  <Legend />
                  <Line type="monotone" dataKey="count" stroke="#8884d8" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            }
          </div>
        </section>

        {/* Blocked URLs Section - Always show */}
        <section className="table-section" style={{ marginTop: 24 }}>
          <div className="table-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <h3 style={{ color: "#ef4444" }}>🚫 Blocked URLs</h3>
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <div className="table-meta" style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <span style={{ color: "#ef4444", fontWeight: 600 }}>{blockedUrls.length}</span> blocked URL{blockedUrls.length !== 1 ? 's' : ''}
                <span style={{ 
                    fontSize: "11px", 
                    color: "#7ee787",
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 4
                  }}>
                    <span style={{
                      width: 8,
                      height: 8,
                      borderRadius: "50%",
                      background: "#7ee787",
                      display: "inline-block",
                      animation: "pulse 2s infinite"
                    }}></span>
                    Live
                </span>
                {lastBlockedUrlsUpdate && (
                  <span style={{ fontSize: "10px", color: "#6e7681" }}>
                    Updated: {lastBlockedUrlsUpdate.toLocaleTimeString('en-US', { hour12: false })}
                  </span>
                )}
              </div>
              <button 
                  onClick={() => setShowBlockedUrls(!showBlockedUrls)}
                  style={{ 
                    padding: "6px 12px", 
                    borderRadius: 8, 
                    border: "1px solid rgba(239, 68, 68, 0.3)", 
                    background: showBlockedUrls ? "rgba(239, 68, 68, 0.2)" : "rgba(255, 255, 255, 0.05)", 
                    color: "#ef4444", 
                    cursor: "pointer",
                    fontSize: "12px",
                    fontWeight: 600,
                    transition: "all 0.2s ease"
                  }}
                  title={showBlockedUrls ? "Hide list" : "Show list"}
                >
                  {showBlockedUrls ? "Hide" : "Show"}
                </button>
            </div>
          </div>

          {showBlockedUrls ? (
            <div className="table-wrap card-visual" style={{ border: "2px solid rgba(239, 68, 68, 0.3)" }}>
              {loadingBlockedUrls ? (
                <div style={{ padding: "40px", textAlign: "center", color: "#6e7681" }}>
                  Loading blocked URLs...
                </div>
              ) : blockedUrls.length === 0 ? (
                <div style={{ padding: "40px", textAlign: "center", color: "#6e7681" }}>
                  No blocked URLs yet. Try accessing a suspicious URL to see it here.
                </div>
              ) : (
                <>
                  <table className="events-table">
                    <thead>
                      <tr>
                        <th style={{ width: "60px" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                            <span>ID</span>
                            <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                              <button
                                onClick={() => {
                                  if (blockedUrlsPage > 0) {
                                    setBlockedUrlsPage(blockedUrlsPage - 1);
                                  }
                                }}
                                disabled={blockedUrlsPage === 0}
                                style={{
                                  padding: "2px 4px",
                                  border: "none",
                                  background: "transparent",
                                  color: blockedUrlsPage === 0 ? "#6e7681" : "#ef4444",
                                  cursor: blockedUrlsPage === 0 ? "not-allowed" : "pointer",
                                  fontSize: "12px",
                                  lineHeight: 1,
                                  display: "flex",
                                  alignItems: "center",
                                  justifyContent: "center"
                                }}
                                title="Previous page"
                              >
                                ↑
                              </button>
                              <button
                                onClick={() => {
                                  const maxPage = Math.ceil(blockedUrls.length / blockedUrlsRowsPerPage) - 1;
                                  if (blockedUrlsPage < maxPage) {
                                    setBlockedUrlsPage(blockedUrlsPage + 1);
                                  }
                                }}
                                disabled={blockedUrlsPage >= Math.ceil(blockedUrls.length / blockedUrlsRowsPerPage) - 1}
                                style={{
                                  padding: "2px 4px",
                                  border: "none",
                                  background: "transparent",
                                  color: blockedUrlsPage >= Math.ceil(blockedUrls.length / blockedUrlsRowsPerPage) - 1 ? "#6e7681" : "#ef4444",
                                  cursor: blockedUrlsPage >= Math.ceil(blockedUrls.length / blockedUrlsRowsPerPage) - 1 ? "not-allowed" : "pointer",
                                  fontSize: "12px",
                                  lineHeight: 1,
                                  display: "flex",
                                  alignItems: "center",
                                  justifyContent: "center"
                                }}
                                title="Next page"
                              >
                                ↓
                              </button>
                            </div>
                          </div>
                        </th>
                        <th>URL</th>
                        <th>ML Score</th>
                        <th>ML Label</th>
                        <th>Timestamp</th>
                      </tr>
                    </thead>
                    <tbody>
                      {blockedUrls
                        .slice(blockedUrlsPage * blockedUrlsRowsPerPage, (blockedUrlsPage + 1) * blockedUrlsRowsPerPage)
                        .map((item, i) => {
                      let timestamp = "-";
                      try {
                        if (item.checked_at) {
                          const ts = new Date(item.checked_at);
                          timestamp = ts.toLocaleString('en-US', { 
                            year: 'numeric', 
                            month: '2-digit', 
                            day: '2-digit',
                            hour: '2-digit', 
                            minute: '2-digit',
                            second: '2-digit',
                            hour12: false
                          });
                        }
                      } catch {}

                      return (
                        <tr 
                          key={i} 
                          className="threat-row"
                          style={{ background: "rgba(239, 68, 68, 0.1)" }}
                        >
                          <td className="id-cell">{item.id || i + 1}</td>
                          <td className="ip-cell" style={{ maxWidth: 400, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            <a 
                              href={item.url} 
                              target="_blank" 
                              rel="noopener noreferrer"
                              style={{ color: "#ef4444", textDecoration: "none" }}
                              onClick={(e) => e.preventDefault()}
                              title={item.url}
                            >
                              {item.url.length > 60 ? item.url.substring(0, 60) + "..." : item.url}
                            </a>
                          </td>
                          <td style={{ color: "#fbbf24", fontWeight: 600 }}>
                            {item.ml_score != null ? item.ml_score.toFixed(3) : "-"}
                          </td>
                          <td>
                            <span className={`status-badge ${item.ml_label === 'malicious' ? 'status-threat' : 'status-safe'}`} style={{ fontSize: "11px" }}>
                              {item.ml_label || "-"}
                            </span>
                          </td>
                          <td className="timestamp-cell" style={{ fontFamily: "monospace", fontSize: "12px" }}>{timestamp}</td>
                        </tr>
                      );
                        })}
                    </tbody>
                  </table>
                  
                  {/* Pagination Controls */}
                  <div style={{ 
                    display: "flex", 
                    justifyContent: "space-between", 
                    alignItems: "center", 
                    padding: "16px 20px",
                    borderTop: "1px solid rgba(255, 255, 255, 0.1)",
                    background: "rgba(0, 0, 0, 0.2)"
                  }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <button
                        onClick={() => {
                          if (blockedUrlsPage > 0) {
                            setBlockedUrlsPage(blockedUrlsPage - 1);
                          }
                        }}
                        disabled={blockedUrlsPage === 0}
                        style={{
                          padding: "8px 16px",
                          borderRadius: 8,
                          border: "1px solid rgba(239, 68, 68, 0.3)",
                          background: blockedUrlsPage === 0 ? "rgba(255, 255, 255, 0.05)" : "rgba(239, 68, 68, 0.2)",
                          color: blockedUrlsPage === 0 ? "#6e7681" : "#ef4444",
                          cursor: blockedUrlsPage === 0 ? "not-allowed" : "pointer",
                          fontSize: "14px",
                          fontWeight: 600,
                          transition: "all 0.2s ease",
                          display: "flex",
                          alignItems: "center",
                          gap: 6
                        }}
                        title="Previous page"
                      >
                        <span>↑</span> Previous
                      </button>
                      
                      <span style={{ 
                        color: "#6e7681", 
                        fontSize: "13px",
                        padding: "0 12px"
                      }}>
                        Page {blockedUrlsPage + 1} of {Math.ceil(blockedUrls.length / blockedUrlsRowsPerPage)} 
                        ({blockedUrlsPage * blockedUrlsRowsPerPage + 1}-{Math.min((blockedUrlsPage + 1) * blockedUrlsRowsPerPage, blockedUrls.length)} of {blockedUrls.length})
                      </span>
                      
                      <button
                        onClick={() => {
                          const maxPage = Math.ceil(blockedUrls.length / blockedUrlsRowsPerPage) - 1;
                          if (blockedUrlsPage < maxPage) {
                            setBlockedUrlsPage(blockedUrlsPage + 1);
                          }
                        }}
                        disabled={blockedUrlsPage >= Math.ceil(blockedUrls.length / blockedUrlsRowsPerPage) - 1}
                        style={{
                          padding: "8px 16px",
                          borderRadius: 8,
                          border: "1px solid rgba(239, 68, 68, 0.3)",
                          background: blockedUrlsPage >= Math.ceil(blockedUrls.length / blockedUrlsRowsPerPage) - 1 ? "rgba(255, 255, 255, 0.05)" : "rgba(239, 68, 68, 0.2)",
                          color: blockedUrlsPage >= Math.ceil(blockedUrls.length / blockedUrlsRowsPerPage) - 1 ? "#6e7681" : "#ef4444",
                          cursor: blockedUrlsPage >= Math.ceil(blockedUrls.length / blockedUrlsRowsPerPage) - 1 ? "not-allowed" : "pointer",
                          fontSize: "14px",
                          fontWeight: 600,
                          transition: "all 0.2s ease",
                          display: "flex",
                          alignItems: "center",
                          gap: 6
                        }}
                        title="Next page"
                      >
                        Next <span>↓</span>
                      </button>
                    </div>
                    
                    <button
                      onClick={() => {
                        if (blockedUrlsRowsPerPage === 2) {
                          setBlockedUrlsRowsPerPage(10);
                          setBlockedUrlsPage(0); // Reset to first page
                        } else {
                          setBlockedUrlsRowsPerPage(2);
                          setBlockedUrlsPage(0); // Reset to first page
                        }
                      }}
                      style={{
                        padding: "8px 16px",
                        borderRadius: 8,
                        border: "1px solid rgba(88, 166, 255, 0.3)",
                        background: "rgba(88, 166, 255, 0.2)",
                        color: "#58a6ff",
                        cursor: "pointer",
                        fontSize: "13px",
                        fontWeight: 600,
                        transition: "all 0.2s ease"
                      }}
                      title={blockedUrlsRowsPerPage === 2 ? "Show 10 rows per page" : "Show 2 rows per page"}
                    >
                      {blockedUrlsRowsPerPage === 2 ? "Show 10 rows" : "Show 2 rows"}
                    </button>
                  </div>
                </>
              )}
            </div>
          ) : null}
        </section>

        {/* Blocked Threats Section */}
        {blockedThreats.length > 0 && (
          <section className="table-section" style={{ marginTop: 24 }}>
            <div className="table-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h3 style={{ color: "#ef4444" }}>🚫 Blocked Threats & URLs</h3>
              <div className="table-meta">{blockedThreats.length} blocked items</div>
            </div>

            <div className="table-wrap card-visual" style={{ border: "2px solid rgba(239, 68, 68, 0.3)" }}>
              <table className="events-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Source IP</th>
                    <th>URL / Threat</th>
                    <th>Threat Type</th>
                    <th>Signatures</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {blockedThreats.map((threat, i) => {
                    const url = threat.url || threat.pkt_hash || "-";
                    const srcIp = threat.src_ip || threat.source_ip || "-";
                    const signatures = threat.signatures || [];
                    const dpiThreats = threat.dpi?.url_validation?.threat_indicators || threat.dpi?.threat_indicators || [];
                    const threatLevel = threat.threat_level || (threat.ml_score > 0.8 ? "high" : "medium");
                    const blocked = threat.blocked || threat.ips_decision?.blocked || false;
                    
                    // Format timestamp
                    let timestamp = "-";
                    try {
                      if (threat.timestamp) {
                        const ts = new Date(threat.timestamp);
                        timestamp = ts.toLocaleString('en-US', { 
                          year: 'numeric', 
                          month: '2-digit', 
                          day: '2-digit',
                          hour: '2-digit', 
                          minute: '2-digit',
                          second: '2-digit'
                        });
                      }
                    } catch {}

                    // Get threat type
                    let threatType = "Unknown";
                    if (signatures.length > 0) {
                      threatType = signatures[0].name;
                    } else if (dpiThreats.length > 0) {
                      threatType = dpiThreats[0];
                    } else if (threat.ml_label === "malicious") {
                      threatType = "ML Detected Threat";
                    }

                    return (
                      <tr 
                        key={i} 
                        className="threat-row"
                        style={{ background: "rgba(239, 68, 68, 0.1)" }}
                      >
                        <td className="id-cell">{threat.id || i + 1}</td>
                        <td className="ip-cell">{srcIp}</td>
                        <td className="ip-cell" style={{ maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {url.length > 50 ? url.substring(0, 50) + "..." : url}
                        </td>
                        <td style={{ color: "#fbbf24" }}>{threatType}</td>
                        <td>
                          {signatures.length > 0 ? (
                            <span style={{ color: "#ef4444", fontSize: "11px" }}>
                              {signatures.length} match{signatures.length > 1 ? "es" : ""}
                            </span>
                          ) : "-"}
                        </td>
                        <td>
                          <span className={`status-badge ${threatLevel === "high" ? "status-threat" : "status-safe"}`} style={{ fontSize: "11px" }}>
                            {threatLevel.toUpperCase()}
                          </span>
                        </td>
                        <td>
                          <span className="status-badge status-threat" style={{ fontSize: "11px" }}>
                            🚫 BLOCKED
                          </span>
                        </td>
                        <td className="timestamp-cell">{timestamp}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>
        )}

        <section className="table-section">
          <div className="table-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <h3>Events Table</h3>
            <div className="table-meta">{loading ? "Loading..." : `${filtered.length} rows`}</div>
          </div>

          <div className="table-wrap card-visual">
            {loading ? (
              <div className="loading">Loading...</div>
            ) : filtered.length === 0 ? (
              <div className="no-data">No records to display.</div>
            ) : (
              <table className="events-table">
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>Source IP</th>
                      <th>Destination IP</th>
                      <th>Source Port</th>
                      <th>Dest Port</th>
                      <th>Protocol</th>
                      <th>Status</th>
                      <th>Timestamp</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.slice(0, eventsDisplayLimit).map((e, i) => {
                      const isLastRow = i === eventsDisplayLimit - 1 && filtered.length > eventsDisplayLimit;
                      // Handle ml_label - determine if safe or threat
                      let isSafe = true;
                      let statusText = "Safe";
                      let statusIcon = "✅";
                      
                      if (e.ml_label === 1 || e.ml_label === "1" || e.ml_label === "malicious") {
                        isSafe = false;
                        statusText = "Threat";
                        statusIcon = "⚠️";
                      } else if (e.ml_label === 0 || e.ml_label === "0" || e.ml_label === "benign") {
                        isSafe = true;
                        statusText = "Safe";
                        statusIcon = "✅";
                      } else if (typeof e.ml_label === "string" && e.ml_label.toLowerCase() === "malicious") {
                        isSafe = false;
                        statusText = "Threat";
                        statusIcon = "⚠️";
                      } else if (typeof e.ml_label === "string" && e.ml_label.toLowerCase() === "benign") {
                        isSafe = true;
                        statusText = "Safe";
                        statusIcon = "✅";
                      } else if (e.ml_score != null && e.ml_score > 0.5) {
                        isSafe = false;
                        statusText = "Suspicious";
                        statusIcon = "🔶";
                      }
                      
                      const score = e.ml_score != null ? Number(e.ml_score).toFixed(3) : "-";
                      
                      // Extract all data
                      const srcIp = e.src_ip ?? e.source_ip ?? "-";
                      const dstIp = e.dst_ip ?? e.dest_ip ?? e.destination_ip ?? "-";
                      const srcPort = e.src_port ?? e.source_port ?? "-";
                      const dstPort = e.dest_port ?? e.dst_port ?? "-";
                      const proto = e.proto ?? e.protocol ?? "-";
                      
                      // Format timestamp
                      let timestamp = "-";
                      try {
                        if (e.timestamp) {
                          const ts = new Date(e.timestamp);
                          timestamp = ts.toLocaleString('en-US', { 
                            year: 'numeric', 
                            month: '2-digit', 
                            day: '2-digit',
                            hour: '2-digit', 
                            minute: '2-digit',
                            second: '2-digit'
                          });
                        }
                      } catch {}
                      
                      return (
                        <tr 
                          key={i} 
                          className={`table-row ${isSafe ? 'safe-row' : 'threat-row'}`}
                          title={isSafe ? "Safe Connection" : "Potential Threat"}
                          onClick={isLastRow ? () => setEventsDisplayLimit(filtered.length) : undefined}
                          style={isLastRow ? { 
                            cursor: "pointer",
                            background: "rgba(88, 166, 255, 0.1)",
                            borderTop: "2px solid rgba(88, 166, 255, 0.3)"
                          } : {}}
                        >
                          <td className="id-cell">{e.id ?? i + 1}</td>
                          <td className="ip-cell">{srcIp}</td>
                          <td className="ip-cell">{dstIp}</td>
                          <td className="port-cell">{srcPort}</td>
                          <td className="port-cell">{dstPort}</td>
                          <td className="proto-cell">
                            <span className={`proto-badge proto-${String(proto).toLowerCase()}`}>
                              {String(proto)}
                            </span>
                          </td>
                          <td className="status-cell">
                            <div className={`status-badge ${isSafe ? 'status-safe' : 'status-threat'}`}>
                              <span className="status-icon">{statusIcon}</span>
                              <span className="status-text">{statusText}</span>
                            </div>
                          </td>
                          <td className="timestamp-cell">
                            {timestamp}
                            {isLastRow && (
                              <span style={{ 
                                display: "block", 
                                fontSize: "11px", 
                                color: "#58a6ff", 
                                marginTop: "4px",
                                fontWeight: 600
                              }}>
                                👆 Click to show all {filtered.length} rows
                              </span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                    {filtered.length > eventsDisplayLimit && (
                      <tr 
                        style={{ 
                          cursor: "pointer",
                          background: "rgba(88, 166, 255, 0.15)",
                          borderTop: "2px solid rgba(88, 166, 255, 0.4)"
                        }}
                        onClick={() => setEventsDisplayLimit(filtered.length)}
                        title={`Click to show all ${filtered.length} rows`}
                      >
                        <td colSpan={8} style={{ 
                          textAlign: "center", 
                          padding: "16px",
                          color: "#58a6ff",
                          fontWeight: 600,
                          fontSize: "14px"
                        }}>
                          👆 Click here to show all {filtered.length} rows ({filtered.length - eventsDisplayLimit} more)
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
            )}
          </div>
        </section>
      </main>

      <footer className="dashboard-footer">
        <div>Built with ❤ — NGFW Team</div>
        <div>{new Date().toLocaleString()}</div>
      </footer>
    </div>
  );
}
