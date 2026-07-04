// ============================================================
// App.jsx  —  React frontend
//
// This file is the ENTIRE user interface.
// It talks to Flask through HTTP requests (fetch).
//
// Sections:
//   1. Imports
//   2. Helper data + functions
//   3. StatCard component
//   4. ClassifyForm component  ← NEW
//   5. Main App component
//      - state variables
//      - useEffect hooks (data loading)
//      - live stream logic
//      - the rendered UI
// ============================================================


// ── 1. IMPORTS ────────────────────────────────────────────────
// "import" brings in code from other files or libraries

import { useState, useEffect, useRef } from "react";
// useState   → stores data that can change (and re-renders UI when it does)
// useEffect  → runs code when something changes (like page load, or state change)
// useRef     → stores a value that does NOT trigger re-render (we use it for the timer)

import {
  ScatterChart, Scatter, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, LineChart, Line, BarChart, Bar, Legend, ReferenceLine
} from "recharts";
// recharts is a charting library — we import only the chart types we need


// ── 2. HELPERS ────────────────────────────────────────────────

// The URL of our Flask server
// Every fetch() call will use this as the base
const API = "http://localhost:5000";

// Color for each packet label
// An object {} in JS works like a dictionary in Python
const COLORS = {
  "DDoS Flood" : "#ff4d6d",
  "Port Scan"  : "#ff9f1c",
  "Data Exfil" : "#c77dff",
  "Suspicious" : "#f72585",
  "Normal"     : "#00f5d4",
};

// A function that looks up a color by label name
// If the label isn't in COLORS, default to teal
const getColor = (label) => COLORS[label] || "#00f5d4";

// Takes all packets + chosen method + threshold
// Adds two new fields to each packet:
//   currentScore  → the score we are currently using (IF or AE)
//   finalDetected → true if the score is above the threshold
function applyThreshold(packets, method, threshold) {
  return packets.map(p => ({
    ...p,
    // ...p means "copy all existing fields from p"
    currentScore: method === "iforest" ? p.iforest_score : p.ae_score,
    // ternary operator: condition ? valueIfTrue : valueIfFalse
    finalDetected: (method === "iforest" ? p.iforest_score : p.ae_score) > threshold,
  }));
  // .map() loops over every packet and returns a new version of it
}

// Custom tooltip shown when you hover over a dot in the scatter chart
const ScatterTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  // ?. is "optional chaining" — if payload is null, don't crash, just return null
  const d = payload[0]?.payload;
  if (!d) return null;
  return (
    <div style={{ background: "#0d1117", border: `1px solid ${getColor(d.label)}`,
      borderRadius: 8, padding: "10px 14px", fontSize: 12, color: "#e6edf3" }}>
      <div style={{ fontWeight: 700, color: getColor(d.label), marginBottom: 6 }}>{d.label}</div>
      <div>Packet Size: <b>{d.packetSize?.toFixed(0)} B</b></div>
      <div>Bytes In: <b>{(d.bytesIn / 1000).toFixed(1)} KB</b></div>
      <div>Protocol: <b>{d.protocol}</b></div>
      <div>Score: <b style={{ color: getColor(d.label) }}>{d.currentScore?.toFixed(3)}</b></div>
    </div>
  );
};


// ── 3. STATCARD COMPONENT ─────────────────────────────────────
// A reusable card that shows one number with a label
// Props (inputs): label, value, sub, color
const StatCard = ({ label, value, sub, color }) => (
  <div style={{ background: "linear-gradient(135deg,#161b22 0%,#0d1117 100%)",
    border: `1px solid ${color}33`, borderRadius: 12, padding: "18px 22px",
    flex: 1, minWidth: 140, position: "relative", overflow: "hidden" }}>
    {/* The glowing circle in the corner — pure CSS trick */}
    <div style={{ position: "absolute", top: -20, right: -20, width: 80, height: 80,
      borderRadius: "50%", background: `${color}15`, filter: "blur(20px)" }} />
    <div style={{ fontSize: 11, color: "#8b949e", letterSpacing: 1.5,
      textTransform: "uppercase", marginBottom: 6 }}>{label}</div>
    <div style={{ fontSize: 32, fontWeight: 800, color,
      fontFamily: "monospace" }}>{value}</div>
    {sub && <div style={{ fontSize: 11, color: "#8b949e", marginTop: 4 }}>{sub}</div>}
    {/* {sub && ...} means: only render this if sub is not empty */}
  </div>
);


// ── 4. CLASSIFY FORM COMPONENT  (NEW) ─────────────────────────
// This is the form where the user types in packet values
// and gets back SAFE or SUSPICIOUS from Flask
const ClassifyForm = () => {

  // Each input field needs its own state variable
  // useState(defaultValue) returns [currentValue, functionToUpdateIt]
  const [form, setForm] = useState({
    packetSize : "500",
    bytesIn    : "1500",
    bytesOut   : "800",
    duration   : "0.5",
    packetsIn  : "10",
    packetsOut : "8",
    flagCount  : "1",
    ttl        : "64",
  });

  // result stores what Flask sends back after classification
  const [result,  setResult]  = useState(null);
  // loading is true while we wait for Flask to respond
  const [loading, setLoading] = useState(false);

  // This runs whenever the user types in any input box
  // e = the event object (contains info about what the user did)
  const handleChange = (e) => {
    setForm({
      ...form,              // copy all existing form values
      [e.target.name]: e.target.value,
      // [e.target.name] is a "computed key" — it uses the input's name attribute
      // e.target.value  is what the user typed
    });
  };

  // This runs when the user clicks "Classify Packet"
  const handleSubmit = async () => {
    // "async" means this function can use "await" inside it
    setLoading(true);   // show a loading state
    setResult(null);    // clear any previous result

    try {
      // fetch() sends an HTTP request to Flask
      const response = await fetch(`${API}/api/classify`, {
        // "await" pauses here until Flask responds
        method : "POST",
        // POST because we are sending data TO Flask
        headers: { "Content-Type": "application/json" },
        // We tell Flask we are sending JSON
        body   : JSON.stringify(form),
        // JSON.stringify converts our JS object to a JSON string
      });

      const data = await response.json();
      // .json() parses Flask's JSON response back into a JS object

      setResult(data);   // store the result so we can show it
    } catch (err) {
      // If something goes wrong (network error, Flask down, etc.)
      console.error("Classify error:", err);
    }

    setLoading(false);   // hide the loading state
  };

  // Small helper to render one input row
  const InputRow = ({ label, name, step = "1" }) => (
    <div style={{ display: "flex", alignItems: "center",
      justifyContent: "space-between", marginBottom: 10 }}>
      <label style={{ fontSize: 12, color: "#8b949e", width: 140 }}>{label}</label>
      <input
        type="number"
        name={name}               // used by handleChange to know which field
        value={form[name]}        // controlled input — value comes from state
        onChange={handleChange}   // called every time user types
        step={step}
        style={{ width: 120, background: "#0d1117", border: "1px solid #30363d",
          borderRadius: 6, padding: "6px 10px", color: "#e6edf3",
          fontSize: 12, fontFamily: "monospace" }}
      />
    </div>
  );

  return (
    <div style={{ background: "#161b22", border: "1px solid #30363d",
      borderRadius: 12, padding: "24px", marginTop: 20 }}>

      {/* Section title */}
      <div style={{ fontSize: 15, fontWeight: 700, color: "#e6edf3", marginBottom: 4 }}>
        Classify Your Own Packet
      </div>
      <div style={{ fontSize: 11, color: "#8b949e", marginBottom: 20 }}>
        Enter packet values → Flask scores it → compares to centroids → SAFE or SUSPICIOUS
      </div>

      {/* Two-column grid for the input fields */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0 40px" }}>
        <InputRow label="Packet Size (bytes)" name="packetSize" step="1"   />
        <InputRow label="Packets In"          name="packetsIn"  step="1"   />
        <InputRow label="Bytes In (bytes)"    name="bytesIn"    step="1"   />
        <InputRow label="Packets Out"         name="packetsOut" step="1"   />
        <InputRow label="Bytes Out (bytes)"   name="bytesOut"   step="1"   />
        <InputRow label="Flag Count"          name="flagCount"  step="1"   />
        <InputRow label="Duration (seconds)"  name="duration"   step="0.01"/>
        <InputRow label="TTL"                 name="ttl"        step="1"   />
      </div>

      {/* Classify button */}
      <button onClick={handleSubmit} disabled={loading}
        style={{ marginTop: 20, padding: "10px 28px",
          background: loading ? "#21262d" : "#00f5d420",
          color: loading ? "#8b949e" : "#00f5d4",
          border: "1px solid #00f5d4", borderRadius: 8,
          cursor: loading ? "not-allowed" : "pointer",
          fontSize: 13, fontWeight: 700, fontFamily: "monospace" }}>
        {loading ? "Classifying..." : "Classify Packet →"}
      </button>

      {/* Result box — only shown when result is not null */}
      {result && (
        <div style={{ marginTop: 24, padding: "20px 24px",
          background: `${result.color}10`,
          border: `2px solid ${result.color}`,
          borderRadius: 10 }}>

          {/* Big result label */}
          <div style={{ fontSize: 28, fontWeight: 800,
            color: result.color, marginBottom: 16, fontFamily: "monospace" }}>
            {result.classification === "SAFE" ? "✓ SAFE" : "⚠ SUSPICIOUS"}
          </div>

          {/* Score details in a grid */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
            {[
              { label: "Isolation Forest Score", value: result.iforest_score },
              { label: "Autoencoder Score",       value: result.ae_score      },
              { label: "Average Score",           value: result.avg_score     },
              { label: "Distance → Normal",       value: result.dist_normal   },
              { label: "Distance → Anomaly",      value: result.dist_anomaly  },
              { label: "Confidence",              value: `${result.confidence}%` },
            ].map(item => (
              // .map() here generates 6 small stat boxes
              <div key={item.label}
                style={{ background: "#0d1117", borderRadius: 8,
                  padding: "12px 14px", border: "1px solid #30363d" }}>
                <div style={{ fontSize: 10, color: "#8b949e",
                  textTransform: "uppercase", letterSpacing: 1, marginBottom: 4 }}>
                  {item.label}
                </div>
                <div style={{ fontSize: 18, fontWeight: 700,
                  color: result.color, fontFamily: "monospace" }}>
                  {item.value}
                </div>
              </div>
            ))}
          </div>

          {/* Plain English explanation */}
          <div style={{ marginTop: 16, fontSize: 12, color: "#8b949e", lineHeight: 1.8 }}>
            The packet scored <b style={{ color: "#e6edf3" }}>{result.avg_score}</b> on average.
            It is <b style={{ color: "#e6edf3" }}>{result.dist_normal}</b> away from the normal centroid
            and <b style={{ color: "#e6edf3" }}>{result.dist_anomaly}</b> away from the anomaly centroid.
            Since it is closer to the{" "}
            <b style={{ color: result.color }}>
              {result.classification === "SAFE" ? "normal" : "anomaly"}
            </b>{" "}
            group, it is classified as{" "}
            <b style={{ color: result.color }}>{result.classification}</b>.
          </div>
        </div>
      )}
    </div>
  );
};


// ── 5. MAIN APP COMPONENT ─────────────────────────────────────
export default function App() {

  // ── State variables ────────────────────────────────────────
  const [raw,       setRaw]       = useState([]);        // raw packets from Flask
  const [scored,    setScored]    = useState([]);        // packets with currentScore added
  const [method,    setMethod]    = useState("iforest"); // which ML method to show
  const [tab,       setTab]       = useState("scatter"); // which chart tab is active
  const [threshold, setThreshold] = useState(0.42);     // detection threshold
  const [streaming, setStreaming] = useState(false);     // is live stream on?
  const [loading,   setLoading]   = useState(true);     // is page still loading?
  const [filterLabel, setFilterLabel] = useState("All");// scatter plot filter

  // useRef stores the interval timer ID
  // We need this to be able to stop the interval later
  const intervalRef = useRef(null);

  // ── Load initial data on page load ────────────────────────
  // useEffect with [] runs ONCE when the component first appears
  useEffect(() => {
    setLoading(true);
    fetch(`${API}/api/data`)
    // fetch() sends a GET request to Flask
      .then(r => r.json())
      // .then() runs when the response arrives — converts it to JS object
      .then(data => {
        setRaw(data);       // store the raw packets
        setLoading(false);  // hide loading screen
      })
      .catch(() => setLoading(false));
      // .catch() handles errors — even if it fails, stop showing loading
  }, []);
  // The [] means "only run this effect once, when component mounts"

  // ── Re-apply threshold whenever method, threshold, or raw data changes ──
  useEffect(() => {
    setScored(applyThreshold(raw, method, threshold));
  }, [raw, method, threshold]);
  // This runs every time raw, method, or threshold changes

  // ── Live stream toggle ────────────────────────────────────
  const toggleStream = () => {
    if (streaming) {
      // If already streaming → stop it
      clearInterval(intervalRef.current);
      // clearInterval() stops the repeating timer
      setStreaming(false);
      return;
    }

    setStreaming(true);
    intervalRef.current = setInterval(() => {
      // setInterval() runs a function repeatedly every N milliseconds
      // 800 ms = 0.8 seconds
      fetch(`${API}/api/packet`)
        .then(r => r.json())
        .then(pkt => {
          setRaw(prev => {
            // prev = the current value of raw before this update
            const next = [...prev.slice(-299), pkt];
            // ...spread operator copies array items
            // .slice(-299) keeps only the last 299 items
            // then we add the new packet at the end
            return next;
          });
        });
    }, 800);
  };

  // Cleanup: stop the interval when the component is removed
  useEffect(() => () => clearInterval(intervalRef.current), []);
  // This returns a "cleanup function" that React calls automatically

  // ── Derived stats (calculated from scored data) ─────────────
  const anomalies     = scored.filter(d => d.finalDetected);
  // .filter() keeps only items where the condition is true

  const normals       = scored.filter(d => !d.finalDetected);
  // !d.finalDetected means "not detected as anomaly"

  const detectionRate = scored.length
    ? ((anomalies.length / scored.length) * 100).toFixed(1)
    : 0;

  const tp        = scored.filter(d => d.finalDetected && d.isAnomaly).length;
  // True Positive = detected as anomaly AND actually is anomaly

  const fp        = scored.filter(d => d.finalDetected && !d.isAnomaly).length;
  // False Positive = detected as anomaly BUT actually is normal

  const precision = anomalies.length
    ? ((tp / anomalies.length) * 100).toFixed(0)
    : 0;

  const displayed = filterLabel === "All"
    ? scored
    : scored.filter(d => d.label === filterLabel);

  // Data for the timeline chart — last 60 packets
  const timelineData = scored.slice(-60).map((d, i) => ({
    i,
    score    : +(d.currentScore || 0).toFixed(3),
    threshold,
    detected : d.finalDetected,
  }));

  // Count anomalies by type for the breakdown chart
  const typeCounts = {};
  anomalies.forEach(d => {
    typeCounts[d.label] = (typeCounts[d.label] || 0) + 1;
    // if typeCounts[d.label] doesn't exist yet, use 0, then add 1
  });
  const barData = Object.entries(typeCounts).map(([k, v]) => ({
    name: k, count: v,
  }));
  // Object.entries() converts an object to an array of [key, value] pairs

  // Score distribution — divide scores into 10 buckets (0-10%, 10-20%, etc.)
  const buckets = Array.from({ length: 10 }, (_, i) => ({
    bucket: `${i*10}-${(i+1)*10}%`, normal: 0, anomaly: 0,
  }));
  scored.forEach(d => {
    const idx = Math.min(Math.floor((d.currentScore || 0) * 10), 9);
    if (d.isAnomaly) buckets[idx].anomaly++;
    else             buckets[idx].normal++;
  });

  const labels = ["All", "Normal", "DDoS Flood", "Port Scan", "Data Exfil", "Suspicious"];


  // ── RENDER ─────────────────────────────────────────────────
  // Everything inside "return" is the actual HTML/JSX that gets shown
  return (
    <div style={{ background: "#0d1117", minHeight: "100vh",
      fontFamily: "monospace", color: "#e6edf3", padding: "24px 28px" }}>

      {/* Google Font */}
      <link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Syne:wght@800&display=swap" rel="stylesheet" />

      {/* ── HEADER ── */}
      <div style={{ display: "flex", alignItems: "center",
        justifyContent: "space-between", marginBottom: 28, flexWrap: "wrap", gap: 12 }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            {/* Blinking dot — green when streaming, amber when loading, red otherwise */}
            <div style={{ width: 10, height: 10, borderRadius: "50%",
              background: loading ? "#ff9f1c" : streaming ? "#00f5d4" : "#ff4d6d",
              animation: (loading || streaming) ? "pulse 1s infinite" : "none" }} />
            <h1 style={{ margin: 0, fontSize: 22, fontFamily: "'Syne',sans-serif",
              fontWeight: 800 }}>
              Network Anomaly <span style={{ color: "#00f5d4" }}>Detection</span>
            </h1>
          </div>
          <div style={{ fontSize: 11, color: "#8b949e", marginTop: 4 }}>
            Python · scikit-learn · Keras · Centroid Classifier · {scored.length} packets
          </div>
        </div>

        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
          {/* Method toggle */}
          <div style={{ display: "flex", background: "#161b22", borderRadius: 8,
            border: "1px solid #30363d", overflow: "hidden" }}>
            {[["iforest","Isolation Forest"], ["autoencoder","Autoencoder"]].map(([v, l]) => (
              <button key={v} onClick={() => setMethod(v)} style={{
                padding: "8px 14px",
                background: method === v ? "#00f5d420" : "transparent",
                color: method === v ? "#00f5d4" : "#8b949e",
                border: "none", borderRight: "1px solid #30363d",
                cursor: "pointer", fontSize: 11, fontFamily: "monospace" }}>
                {l}
              </button>
            ))}
          </div>

          {/* Live stream button */}
          <button onClick={toggleStream} style={{
            padding: "8px 16px",
            background: streaming ? "#ff4d6d20" : "#00f5d420",
            color: streaming ? "#ff4d6d" : "#00f5d4",
            border: `1px solid ${streaming ? "#ff4d6d" : "#00f5d4"}`,
            borderRadius: 8, cursor: "pointer",
            fontSize: 11, fontWeight: 700, fontFamily: "monospace" }}>
            {streaming ? "⏹ STOP STREAM" : "▶ LIVE STREAM"}
          </button>

          {/* Download Excel button — clicking opens /api/download */}
          <a href={`${API}/api/download`} download
            style={{ padding: "8px 16px",
              background: "#58a6ff20", color: "#58a6ff",
              border: "1px solid #58a6ff", borderRadius: 8,
              cursor: "pointer", fontSize: 11,
              fontWeight: 700, fontFamily: "monospace",
              textDecoration: "none", display: "inline-block" }}>
            ⬇ Download Excel
          </a>
          {/* <a href=...> is a link. "download" attribute makes it download instead of navigate */}
        </div>
      </div>

      {/* ── LOADING STATE ── */}
      {loading && (
        <div style={{ textAlign: "center", padding: "80px 0", color: "#8b949e" }}>
          <div style={{ fontSize: 14, marginBottom: 8 }}>
            ⏳ Flask is training models + generating Excel...
          </div>
          <div style={{ fontSize: 11 }}>Takes about 30 seconds on first run</div>
        </div>
      )}

      {/* ── MAIN CONTENT — only shown after loading ── */}
      {/* {!loading && <> ... </>} means: if not loading, show everything inside */}
      {!loading && <>

        {/* ── STAT CARDS ── */}
        <div style={{ display: "flex", gap: 12, marginBottom: 24, flexWrap: "wrap" }}>
          <StatCard label="Total Packets"  value={scored.length}     sub="analyzed"                color="#58a6ff" />
          <StatCard label="Anomalies"      value={anomalies.length}  sub={`${detectionRate}% of traffic`} color="#ff4d6d" />
          <StatCard label="Normal"         value={normals.length}    sub="baseline traffic"        color="#00f5d4" />
          <StatCard label="Precision"      value={`${precision}%`}   sub={`${tp} true positives`} color="#c77dff" />
          <StatCard label="False Pos."     value={fp}                sub="review needed"           color="#ff9f1c" />
        </div>

        {/* ── THRESHOLD SLIDER ── */}
        <div style={{ background: "#161b22", border: "1px solid #30363d",
          borderRadius: 10, padding: "12px 18px", marginBottom: 20,
          display: "flex", alignItems: "center", gap: 16, flexWrap: "wrap" }}>
          <span style={{ fontSize: 11, color: "#8b949e",
            textTransform: "uppercase", letterSpacing: 1 }}>Threshold</span>
          <input type="range" min={0.1} max={0.9} step={0.01}
            value={threshold} onChange={e => setThreshold(+e.target.value)}
            style={{ flex: 1, minWidth: 200, accentColor: "#00f5d4" }} />
          <span style={{ fontSize: 14, color: "#00f5d4",
            fontWeight: 700, minWidth: 40 }}>{threshold.toFixed(2)}</span>
          <span style={{ fontSize: 11, color: "#8b949e" }}>Lower = more sensitive</span>
        </div>

        {/* ── CHART TABS ── */}
        <div style={{ display: "flex", gap: 8, marginBottom: 20, flexWrap: "wrap" }}>
          {[["scatter","Scatter Plot"],["timeline","Score Timeline"],
            ["distribution","Distribution"],["breakdown","Anomaly Types"]].map(([v, l]) => (
            <button key={v} onClick={() => setTab(v)} style={{
              padding: "8px 16px",
              background: tab === v ? "#00f5d420" : "#161b22",
              color: tab === v ? "#00f5d4" : "#8b949e",
              border: `1px solid ${tab === v ? "#00f5d4" : "#30363d"}`,
              borderRadius: 8, cursor: "pointer",
              fontSize: 11, fontFamily: "monospace" }}>{l}</button>
          ))}
        </div>

        {/* ── CHART AREA ── */}
        <div style={{ background: "#161b22", border: "1px solid #30363d",
          borderRadius: 12, padding: "20px 16px", marginBottom: 24 }}>

          {/* SCATTER PLOT */}
          {tab === "scatter" && (<>
            <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
              {labels.map(l => (
                <button key={l} onClick={() => setFilterLabel(l)} style={{
                  padding: "4px 12px",
                  background: filterLabel === l ? `${getColor(l)}25` : "transparent",
                  color: filterLabel === l ? getColor(l) : "#8b949e",
                  border: `1px solid ${filterLabel === l ? getColor(l) : "#30363d"}`,
                  borderRadius: 20, cursor: "pointer",
                  fontSize: 11, fontFamily: "monospace" }}>{l}</button>
              ))}
            </div>
            <ResponsiveContainer width="100%" height={340}>
              <ScatterChart margin={{ top: 10, right: 20, bottom: 20, left: 0 }}>
                <CartesianGrid stroke="#21262d" strokeDasharray="3 3" />
                <XAxis dataKey="packetSize" name="Packet Size" unit=" B"
                  tick={{ fill: "#8b949e", fontSize: 11 }}
                  label={{ value: "Packet Size (bytes)", position: "insideBottom",
                    offset: -10, fill: "#8b949e", fontSize: 11 }} />
                <YAxis dataKey="bytesIn" tick={{ fill: "#8b949e", fontSize: 11 }}
                  label={{ value: "Bytes In", angle: -90,
                    position: "insideLeft", fill: "#8b949e", fontSize: 11 }} />
                <Tooltip content={<ScatterTooltip />} />
                {labels.filter(l => l !== "All").map(l => (
                  <Scatter key={l} name={l}
                    data={displayed.filter(d => d.label === l)}
                    shape={props => (
                      <circle key={props.key} cx={props.cx} cy={props.cy}
                        r={props.payload.finalDetected ? 6 : 4}
                        fill={getColor(props.payload.label)}
                        stroke={props.payload.finalDetected ? "#fff" : "none"}
                        strokeWidth={1} opacity={0.85} />
                    )} />
                ))}
              </ScatterChart>
            </ResponsiveContainer>
            <div style={{ display: "flex", gap: 16,
              justifyContent: "center", flexWrap: "wrap", marginTop: 10 }}>
              {Object.entries(COLORS).map(([k, v]) => (
                <div key={k} style={{ display: "flex",
                  alignItems: "center", gap: 6, fontSize: 11, color: "#8b949e" }}>
                  <div style={{ width: 10, height: 10,
                    borderRadius: "50%", background: v }} /> {k}
                </div>
              ))}
            </div>
          </>)}

          {/* SCORE TIMELINE */}
          {tab === "timeline" && (<>
            <div style={{ fontSize: 12, color: "#8b949e", marginBottom: 12 }}>
              Anomaly score for the last 60 packets. Spikes above the red line = detected threats.
            </div>
            <ResponsiveContainer width="100%" height={340}>
              <LineChart data={timelineData}
                margin={{ top: 10, right: 20, bottom: 20, left: 0 }}>
                <CartesianGrid stroke="#21262d" strokeDasharray="3 3" />
                <XAxis dataKey="i" tick={{ fill: "#8b949e", fontSize: 10 }}
                  label={{ value: "Packet Index", position: "insideBottom",
                    offset: -10, fill: "#8b949e", fontSize: 11 }} />
                <YAxis domain={[0, 1]} tick={{ fill: "#8b949e", fontSize: 10 }} />
                <Tooltip contentStyle={{ background: "#0d1117",
                  border: "1px solid #30363d", borderRadius: 8, fontSize: 11 }} />
                <ReferenceLine y={threshold} stroke="#ff4d6d" strokeDasharray="6 3"
                  label={{ value: `Threshold ${threshold.toFixed(2)}`,
                    fill: "#ff4d6d", fontSize: 10, position: "insideTopRight" }} />
                <Line type="monotone" dataKey="score" stroke="#00f5d4" strokeWidth={2}
                  dot={props => (
                    <circle key={props.key} cx={props.cx} cy={props.cy}
                      r={props.payload.detected ? 5 : 2}
                      fill={props.payload.detected ? "#ff4d6d" : "#00f5d4"}
                      stroke="none" opacity={0.9} />
                  )} />
              </LineChart>
            </ResponsiveContainer>
          </>)}

          {/* SCORE DISTRIBUTION */}
          {tab === "distribution" && (<>
            <div style={{ fontSize: 12, color: "#8b949e", marginBottom: 12 }}>
              Normal traffic clusters near 0. Anomalies push toward 1.
            </div>
            <ResponsiveContainer width="100%" height={340}>
              <BarChart data={buckets} margin={{ top:10, right:20, bottom:30, left:0 }}>
                <CartesianGrid stroke="#21262d" strokeDasharray="3 3" />
                <XAxis dataKey="bucket" tick={{ fill: "#8b949e", fontSize: 9 }}
                  label={{ value: "Score Bucket", position: "insideBottom",
                    offset: -15, fill: "#8b949e", fontSize: 11 }} />
                <YAxis tick={{ fill: "#8b949e", fontSize: 10 }} />
                <Tooltip contentStyle={{ background: "#0d1117",
                  border: "1px solid #30363d", borderRadius: 8, fontSize: 11 }} />
                <Legend wrapperStyle={{ fontSize: 11, color: "#8b949e" }} />
                <Bar dataKey="normal"  name="Normal"  fill="#00f5d4"
                  opacity={0.8} radius={[4,4,0,0]} />
                <Bar dataKey="anomaly" name="Anomaly" fill="#ff4d6d"
                  opacity={0.8} radius={[4,4,0,0]} />
              </BarChart>
            </ResponsiveContainer>
          </>)}

          {/* ANOMALY TYPE BREAKDOWN */}
          {tab === "breakdown" && (<>
            <div style={{ fontSize: 12, color: "#8b949e", marginBottom: 12 }}>
              Detected anomalies broken down by attack type.
            </div>
            <ResponsiveContainer width="100%" height={340}>
              <BarChart data={barData} layout="vertical"
                margin={{ top:10, right:30, bottom:10, left:70 }}>
                <CartesianGrid stroke="#21262d" strokeDasharray="3 3" horizontal={false} />
                <XAxis type="number" tick={{ fill: "#8b949e", fontSize: 10 }} />
                <YAxis type="category" dataKey="name"
                  tick={{ fill: "#8b949e", fontSize: 11 }} width={80} />
                <Tooltip contentStyle={{ background: "#0d1117",
                  border: "1px solid #30363d", borderRadius: 8, fontSize: 11 }} />
                <Bar dataKey="count" radius={[0,6,6,0]}
                  fill="#00f5d4"
                  label={{ position: "right", fill: "#8b949e", fontSize: 11 }} />
              </BarChart>
            </ResponsiveContainer>
          </>)}
        </div>

        {/* ── LIVE TRAFFIC TABLE ── */}
        <div style={{ background: "#161b22", border: "1px solid #30363d",
          borderRadius: 12, overflow: "hidden" }}>
          <div style={{ padding: "14px 20px", borderBottom: "1px solid #30363d",
            display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: 13, fontWeight: 700 }}>Live Traffic Log</span>
            <span style={{ fontSize: 11, color: "#8b949e" }}>last 12 packets</span>
          </div>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
              <thead>
                <tr style={{ background: "#0d1117" }}>
                  {["#","Protocol","Pkt Size","Bytes In","Bytes Out",
                    "Port","Score","Status"].map(h => (
                    <th key={h} style={{ padding: "10px 14px", color: "#8b949e",
                      textAlign: "left", fontWeight: 400, whiteSpace: "nowrap" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {scored.slice(-12).reverse().map(d => {
                  const detected = d.finalDetected;
                  const missed   = !detected && d.isAnomaly;
                  const color    = detected ? getColor(d.label)
                                 : missed   ? "#ff9f1c"
                                 :            "#00f5d4";
                  const text     = detected ? `⚠ ${d.label}`
                                 : missed   ? `~ ${d.label}`
                                 :            "✓ Normal";
                  return (
                    <tr key={d.id} style={{ borderTop: "1px solid #21262d",
                      background: detected ? `${getColor(d.label)}10` : "transparent" }}>
                      <td style={{ padding:"9px 14px", color:"#8b949e" }}>{d.id}</td>
                      <td style={{ padding:"9px 14px", color:"#58a6ff" }}>{d.protocol}</td>
                      <td style={{ padding:"9px 14px" }}>{d.packetSize?.toFixed(0)}B</td>
                      <td style={{ padding:"9px 14px" }}>{(d.bytesIn/1000).toFixed(1)}KB</td>
                      <td style={{ padding:"9px 14px" }}>{(d.bytesOut/1000).toFixed(1)}KB</td>
                      <td style={{ padding:"9px 14px", color:"#8b949e" }}>{d.port}</td>
                      <td style={{ padding:"9px 14px" }}>
                        <div style={{ display:"flex", alignItems:"center", gap:6 }}>
                          <div style={{ width:40, height:4, background:"#21262d",
                            borderRadius:2, overflow:"hidden" }}>
                            <div style={{ width:`${Math.min((d.currentScore||0)*100,100)}%`,
                              height:"100%", borderRadius:2,
                              background: detected ? getColor(d.label) : "#00f5d4" }} />
                          </div>
                          <span style={{ color: detected ? getColor(d.label) : "#8b949e" }}>
                            {(d.currentScore||0).toFixed(3)}
                          </span>
                        </div>
                      </td>
                      <td style={{ padding:"9px 14px" }}>
                        <span style={{ padding:"3px 8px", borderRadius:4, fontSize:10,
                          fontWeight:700, background:`${color}25`, color }}>
                          {text}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* ── CLASSIFY FORM (NEW) ── */}
        <ClassifyForm />

        {/* ── MODEL INFO CARDS ── */}
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr",
          gap:16, marginTop:20 }}>
          {[
            { title:"Isolation Forest (sklearn)", color:"#00f5d4",
              active: method==="iforest",
              desc:"100 trees · contamination=0.08. Anomalies are isolated in fewer random splits. Sigmoid scoring — works for any batch size including 1 packet." },
            { title:"Autoencoder (Keras)", color:"#c77dff",
              active: method==="autoencoder",
              desc:"Dense 8→6→3→6→8 · Adam · MSE loss · 60 epochs. Trained only on normal traffic. High reconstruction error = anomaly." },
          ].map(m => (
            <div key={m.title} style={{ background: m.active ? `${m.color}08` : "#161b22",
              border:`1px solid ${m.active ? m.color : "#30363d"}`,
              borderRadius:10, padding:"16px 20px" }}>
              <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:8 }}>
                <div style={{ width:8, height:8, borderRadius:"50%",
                  background: m.active ? m.color : "#30363d" }} />
                <span style={{ fontWeight:700, fontSize:13,
                  color: m.active ? m.color : "#8b949e" }}>{m.title}</span>
                {m.active && <span style={{ fontSize:9, padding:"2px 6px",
                  borderRadius:4, background:`${m.color}25`,
                  color:m.color }}>ACTIVE</span>}
              </div>
              <p style={{ margin:0, fontSize:11,
                color:"#8b949e", lineHeight:1.7 }}>{m.desc}</p>
            </div>
          ))}
        </div>

      </>}

      {/* CSS animation for the blinking dot */}
      <style>{`
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.3} }
      `}</style>

    </div>
  );
}
