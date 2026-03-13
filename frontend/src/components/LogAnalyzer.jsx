import { useState, useRef, useMemo } from 'react'
import { Upload, FileText, AlertTriangle, CheckCircle2, Loader2, X, Shield, Target, Search, SlidersHorizontal } from 'lucide-react'

const SEVERITY_COLORS = {
  CRITICAL: 'bg-red-900/40 text-red-400 border border-red-800',
  WARNING:  'bg-amber-900/40 text-amber-400 border border-amber-800',
  INFO:     'bg-emerald-900/40 text-emerald-400 border border-emerald-800',
}
const SEVERITY_BAR = {
  CRITICAL: 'bg-red-500',
  WARNING:  'bg-amber-400',
  INFO:     'bg-emerald-400',
}
const TACTIC_COLORS = [
  'bg-purple-900/50 text-purple-300 border border-purple-800',
  'bg-blue-900/50 text-blue-300 border border-blue-800',
  'bg-teal-900/50 text-teal-300 border border-teal-800',
  'bg-orange-900/50 text-orange-300 border border-orange-800',
  'bg-pink-900/50 text-pink-300 border border-pink-800',
  'bg-indigo-900/50 text-indigo-300 border border-indigo-800',
]
function tacticColor(i) { return TACTIC_COLORS[i % TACTIC_COLORS.length] }

export default function LogAnalyzer() {
  const [file,           setFile]           = useState(null)
  const [dragging,       setDragging]       = useState(false)
  const [loading,        setLoading]        = useState(false)
  const [result,         setResult]         = useState(null)
  const [error,          setError]          = useState(null)
  const [alertPage,      setAlertPage]      = useState(1)
  const [expanded,       setExpanded]       = useState(null)
  // filters
  const [searchQ,        setSearchQ]        = useState('')
  const [filterSeverity, setFilterSeverity] = useState('')
  const [filterType,     setFilterType]     = useState('')
  const [filterTactic,   setFilterTactic]   = useState('')
  const inputRef = useRef()

  const ALERTS_PER_PAGE = 25

  // Derive unique option lists from result
  const typeOptions   = useMemo(() => result ? [...new Set(result.alerts.map(a => a.event_type).filter(Boolean))].sort() : [], [result])
  const tacticOptions = useMemo(() => result ? [...new Set(result.alerts.flatMap(a => Array.isArray(a.mitre_tactics) ? a.mitre_tactics : []).filter(Boolean))].sort() : [], [result])

  // Filtered alerts
  const filteredAlerts = useMemo(() => {
    if (!result) return []
    const q = searchQ.toLowerCase().trim()
    return result.alerts.filter(a => {
      if (filterSeverity && a.severity !== filterSeverity) return false
      if (filterType     && a.event_type !== filterType)   return false
      if (filterTactic   && !(Array.isArray(a.mitre_tactics) && a.mitre_tactics.includes(filterTactic))) return false
      if (q) {
        const haystack = [
          a.description, a.source_ip, a.event_type,
          a.sigma_rule_title, a.raw_log,
          ...(Array.isArray(a.matched_keywords) ? a.matched_keywords : []),
          ...(Array.isArray(a.mitre_tactics) ? a.mitre_tactics : []),
          ...(Array.isArray(a.mitre_techniques) ? a.mitre_techniques : []),
        ].filter(Boolean).join(' ').toLowerCase()
        if (!haystack.includes(q)) return false
      }
      return true
    })
  }, [result, searchQ, filterSeverity, filterType, filterTactic])

  function resetFilters() {
    setSearchQ(''); setFilterSeverity(''); setFilterType(''); setFilterTactic(''); setAlertPage(1)
  }
  const hasFilters = searchQ || filterSeverity || filterType || filterTactic

  function handleFile(f) { setFile(f); setResult(null); setError(null) }
  function onInputChange(e) { if (e.target.files[0]) handleFile(e.target.files[0]) }
  function onDrop(e) {
    e.preventDefault(); setDragging(false)
    const f = e.dataTransfer.files[0]
    if (f) handleFile(f)
  }
  function clearAll() {
    setFile(null); setResult(null); setError(null)
    if (inputRef.current) inputRef.current.value = ''
  }
  function toggleExpand(i) { setExpanded(e => e === i ? null : i) }

  async function analyze() {
    if (!file) return
    setLoading(true); setError(null); setResult(null); setAlertPage(1); resetFilters()
    const form = new FormData()
    form.append('file', file)
    try {
      const res = await fetch('/api/analyze', { method: 'POST', body: form })
      if (!res.ok) { const err = await res.json(); throw new Error(err.detail ?? 'Analysis failed') }
      setResult(await res.json())
    } catch (e) { setError(e.message) }
    finally { setLoading(false) }
  }

  const totalPages  = Math.max(1, Math.ceil(filteredAlerts.length / ALERTS_PER_PAGE))
  const pagedAlerts = filteredAlerts.slice((alertPage - 1) * ALERTS_PER_PAGE, alertPage * ALERTS_PER_PAGE)
  const maxSevCount = result ? Math.max(...result.by_severity.map(s => s.count), 1) : 1

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold text-slate-100">Log File Analyzer</h1>

      {/* Drop zone */}
      <div
        onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => !file && inputRef.current?.click()}
        className={`relative border-2 border-dashed rounded-xl p-10 flex flex-col items-center justify-center gap-3 transition-colors cursor-pointer
          ${dragging ? 'border-cyan-500 bg-cyan-900/10' : 'border-slate-700 bg-slate-900 hover:border-slate-500'}`}
      >
        <input ref={inputRef} type="file" accept=".log,.txt,text/plain" className="hidden" onChange={onInputChange} />
        {file ? (
          <div className="flex items-center gap-3">
            <FileText size={28} className="text-cyan-400 shrink-0" />
            <div>
              <p className="text-slate-200 font-medium">{file.name}</p>
              <p className="text-slate-500 text-xs">{(file.size / 1024).toFixed(1)} KB</p>
            </div>
            <button onClick={(e) => { e.stopPropagation(); clearAll() }} className="ml-4 text-slate-500 hover:text-slate-300 transition">
              <X size={16} />
            </button>
          </div>
        ) : (
          <>
            <Upload size={32} className="text-slate-500" />
            <p className="text-slate-400 text-sm">Drag & drop a <span className="text-cyan-400">.log</span> or <span className="text-cyan-400">.txt</span> file, or click to browse</p>
          </>
        )}
      </div>

      {/* Action bar */}
      <div className="flex items-center gap-4">
        <button onClick={analyze} disabled={!file || loading}
          className="flex items-center gap-2 px-6 py-2.5 bg-cyan-700 hover:bg-cyan-600 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-medium rounded-lg transition-colors">
          {loading ? <Loader2 size={16} className="animate-spin" /> : <Upload size={16} />}
          {loading ? 'Analyzing…' : 'Analyze File'}
        </button>
        {result && <span className="text-sm text-emerald-400 flex items-center gap-1.5"><CheckCircle2 size={15} /> Analysis complete</span>}
        {error   && <span className="text-sm text-red-400 flex items-center gap-1.5"><AlertTriangle size={15} /> {error}</span>}
      </div>

      {/* Results */}
      {result && (
        <div className="space-y-6">

          {/* Summary cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <StatCard label="Lines Processed" value={result.lines_processed.toLocaleString()} color="text-cyan-400"    bg="bg-cyan-900/20 border-cyan-800/40" />
            <StatCard label="Alerts Found"    value={result.alerts_found.toLocaleString()}    color="text-red-400"     bg="bg-red-900/20 border-red-800/40" />
            <StatCard label="Critical"        value={(result.by_severity.find(s=>s.severity==='CRITICAL')?.count ?? 0).toLocaleString()} color="text-red-400"    bg="bg-red-900/20 border-red-800/40" />
            <StatCard label="Warning"         value={(result.by_severity.find(s=>s.severity==='WARNING')?.count ?? 0).toLocaleString()}  color="text-amber-400"  bg="bg-amber-900/20 border-amber-800/40" />
          </div>

          {/* Breakdown grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* By severity */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
              <h2 className="text-sm font-semibold text-slate-400 mb-4">By Severity</h2>
              <div className="space-y-3">
                {result.by_severity.map(s => (
                  <div key={s.severity} className="flex items-center gap-3">
                    <span className={`text-xs px-2 py-0.5 rounded-full font-medium shrink-0 ${SEVERITY_COLORS[s.severity] ?? ''}`}>{s.severity}</span>
                    <div className="flex-1 bg-slate-800 rounded-full h-2">
                      <div className={`h-2 rounded-full ${SEVERITY_BAR[s.severity] ?? 'bg-slate-500'}`} style={{ width: `${(s.count / maxSevCount) * 100}%` }} />
                    </div>
                    <span className="text-xs text-slate-400 w-10 text-right">{s.count.toLocaleString()}</span>
                  </div>
                ))}
                {result.by_severity.length === 0 && <p className="text-slate-500 text-sm text-center py-4">No alerts</p>}
              </div>
            </div>

            {/* By attack type */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
              <h2 className="text-sm font-semibold text-slate-400 mb-4">By Attack Type</h2>
              <div className="space-y-2 max-h-52 overflow-y-auto">
                {result.by_type.map(t => (
                  <div key={t.event_type} className="flex items-center justify-between text-sm">
                    <span className="text-slate-300 truncate">{t.event_type.replace(/_/g, ' ')}</span>
                    <span className="text-cyan-400 font-mono font-medium shrink-0 ml-3">{t.count.toLocaleString()}</span>
                  </div>
                ))}
                {result.by_type.length === 0 && <p className="text-slate-500 text-sm text-center py-4">No threats</p>}
              </div>
            </div>

            {/* MITRE Tactics */}
            {result.by_tactic && result.by_tactic.length > 0 && (
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
                <h2 className="text-sm font-semibold text-slate-400 mb-4 flex items-center gap-2">
                  <Shield size={13} className="text-purple-400" /> MITRE ATT&CK Tactics
                </h2>
                <div className="space-y-2">
                  {result.by_tactic.map((t, i) => (
                    <div key={t.tactic} className="flex items-center justify-between">
                      <span className={`text-xs px-2 py-0.5 rounded font-medium ${tacticColor(i)}`}>{t.tactic}</span>
                      <span className="text-slate-400 text-xs font-mono">{t.count.toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* MITRE Techniques */}
            {result.by_technique && result.by_technique.length > 0 && (
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
                <h2 className="text-sm font-semibold text-slate-400 mb-4 flex items-center gap-2">
                  <Target size={13} className="text-cyan-400" /> MITRE ATT&CK Techniques
                </h2>
                <div className="space-y-2 max-h-52 overflow-y-auto">
                  {result.by_technique.map(t => (
                    <div key={t.technique} className="flex items-center justify-between">
                      <a href={`https://attack.mitre.org/techniques/${t.technique.replace('.','/')}`}
                        target="_blank" rel="noreferrer"
                        className="text-xs text-cyan-400 hover:text-cyan-300 underline font-mono">{t.technique}</a>
                      <span className="text-slate-400 text-xs font-mono">{t.count.toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Alert details table */}
          {result.alerts.length > 0 && (
            <div className="space-y-3">
              <div className="flex flex-col gap-3">
                <h2 className="text-sm font-semibold text-slate-400 flex items-center gap-2">
                  <SlidersHorizontal size={13} className="text-slate-500" />
                  Detected Alerts
                  <span className="text-slate-500 font-normal">
                    ({hasFilters ? `${filteredAlerts.length.toLocaleString()} of ` : ''}{result.alerts.length.toLocaleString()})
                  </span>
                </h2>

                {/* Search + Filters */}
                <div className="flex flex-wrap gap-2 items-center">
                  {/* Search input */}
                  <div className="relative flex-1 min-w-[200px]">
                    <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
                    <input
                      type="text"
                      value={searchQ}
                      onChange={e => { setSearchQ(e.target.value); setAlertPage(1) }}
                      placeholder="Search description, IP, keywords, rule…"
                      className="w-full pl-8 pr-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-600 transition"
                    />
                  </div>

                  {/* Severity filter */}
                  <select
                    value={filterSeverity}
                    onChange={e => { setFilterSeverity(e.target.value); setAlertPage(1) }}
                    className="px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-300 focus:outline-none focus:border-cyan-600 transition cursor-pointer"
                  >
                    <option value="">All Severities</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="WARNING">Warning</option>
                    <option value="INFO">Info</option>
                  </select>

                  {/* Event type filter */}
                  {typeOptions.length > 0 && (
                    <select
                      value={filterType}
                      onChange={e => { setFilterType(e.target.value); setAlertPage(1) }}
                      className="px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-300 focus:outline-none focus:border-cyan-600 transition cursor-pointer max-w-[220px]"
                    >
                      <option value="">All Attack Types</option>
                      {typeOptions.map(t => (
                        <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>
                      ))}
                    </select>
                  )}

                  {/* MITRE tactic filter */}
                  {tacticOptions.length > 0 && (
                    <select
                      value={filterTactic}
                      onChange={e => { setFilterTactic(e.target.value); setAlertPage(1) }}
                      className="px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-300 focus:outline-none focus:border-cyan-600 transition cursor-pointer max-w-[200px]"
                    >
                      <option value="">All MITRE Tactics</option>
                      {tacticOptions.map(t => (
                        <option key={t} value={t}>{t}</option>
                      ))}
                    </select>
                  )}

                  {/* Reset */}
                  {hasFilters && (
                    <button
                      onClick={resetFilters}
                      className="flex items-center gap-1.5 px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-300 text-sm rounded-lg transition"
                    >
                      <X size={13} /> Clear
                    </button>
                  )}
                </div>

                {/* No results message */}
                {filteredAlerts.length === 0 && (
                  <div className="flex items-center justify-center h-24 text-slate-500 text-sm gap-2">
                    <Search size={16} /> No alerts match your filters.
                  </div>
                )}
              </div>
              {filteredAlerts.length > 0 && (
              <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 text-xs uppercase">
                      <th className="px-3 py-3 text-left w-6"></th>
                      <th className="px-4 py-3 text-left">Severity</th>
                      <th className="px-4 py-3 text-left">Event Type</th>
                      <th className="px-4 py-3 text-left">Source IP</th>
                      <th className="px-4 py-3 text-left">Description</th>
                      <th className="px-4 py-3 text-left">MITRE</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pagedAlerts.map((a, idx) => {
                      const globalIdx = (alertPage - 1) * ALERTS_PER_PAGE + idx
                      const isOpen = expanded === globalIdx
                      return (
                        <>
                          <tr key={globalIdx} onClick={() => toggleExpand(globalIdx)}
                            className="border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors cursor-pointer">
                            <td className="px-3 py-2.5 text-slate-600">
                              <span className="text-[10px]">{isOpen ? '▲' : '▼'}</span>
                            </td>
                            <td className="px-4 py-2.5">
                              <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${SEVERITY_COLORS[a.severity] ?? ''}`}>{a.severity}</span>
                            </td>
                            <td className="px-4 py-2.5 text-slate-300 whitespace-nowrap">{a.event_type?.replace(/_/g,' ')}</td>
                            <td className="px-4 py-2.5 text-cyan-400 font-mono">{a.source_ip}</td>
                            <td className="px-4 py-2.5 text-slate-300 max-w-[260px] truncate">{a.description}</td>
                            <td className="px-4 py-2.5">
                              <div className="flex flex-wrap gap-1">
                                {Array.isArray(a.mitre_tactics) && a.mitre_tactics.map((t, i) => (
                                  <span key={t} className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${tacticColor(i)}`}>{t}</span>
                                ))}
                                {Array.isArray(a.mitre_techniques) && a.mitre_techniques.map(t => (
                                  <span key={t} className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-900/50 text-cyan-300 border border-cyan-800 font-mono">{t}</span>
                                ))}
                              </div>
                            </td>
                          </tr>
                          {isOpen && (
                            <tr key={`${globalIdx}-d`} className="bg-slate-800/40 border-b border-slate-700">
                              <td colSpan={6} className="px-6 py-3">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                                  <div>
                                    <p className="text-slate-500 mb-1 uppercase tracking-wide font-semibold">Sigma Rule</p>
                                    <p className="text-slate-300">{a.sigma_rule_title || '—'}</p>
                                    {a.sigma_rule_id && <p className="text-slate-600 font-mono mt-0.5">{a.sigma_rule_id}</p>}
                                  </div>
                                  <div>
                                    <p className="text-slate-500 mb-1 uppercase tracking-wide font-semibold">Matched Keywords</p>
                                    <div className="flex flex-wrap gap-1">
                                      {Array.isArray(a.matched_keywords) && a.matched_keywords.length > 0
                                        ? a.matched_keywords.slice(0,8).map(k => (
                                            <span key={k} className="bg-slate-700 text-slate-300 px-1.5 py-0.5 rounded font-mono">{k}</span>
                                          ))
                                        : <span className="text-slate-600">—</span>
                                      }
                                    </div>
                                  </div>
                                  <div className="md:col-span-2">
                                    <p className="text-slate-500 mb-1 uppercase tracking-wide font-semibold">Raw Log</p>
                                    <p className="text-slate-400 font-mono bg-slate-900 rounded px-2 py-1 break-all">{a.raw_log || '—'}</p>
                                  </div>
                                </div>
                              </td>
                            </tr>
                          )}
                        </>
                      )
                    })}
                  </tbody>
                </table>
              </div>
              )}

              {/* Pagination */}
              {totalPages > 1 && filteredAlerts.length > 0 && (
                <div className="flex items-center justify-between text-sm text-slate-400">
                  <span>{filteredAlerts.length.toLocaleString()} alert{filteredAlerts.length !== 1 ? 's' : ''}{hasFilters ? ` matched` : ''}</span>
                  <div className="flex items-center gap-2">
                    <button disabled={alertPage <= 1} onClick={() => setAlertPage(p => p - 1)}
                      className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-30 transition text-xs">Prev</button>
                    <span>Page {alertPage} of {totalPages}</span>
                    <button disabled={alertPage >= totalPages} onClick={() => setAlertPage(p => p + 1)}
                      className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-30 transition text-xs">Next</button>
                  </div>
                </div>
              )}
            </div>
          )}

          {result.alerts.length === 0 && (
            <div className="flex flex-col items-center justify-center h-32 text-slate-500 gap-2">
              <CheckCircle2 size={28} className="text-emerald-500" />
              <p>No threats detected in this file.</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function StatCard({ label, value, color, bg }) {
  return (
    <div className={`border rounded-xl p-4 ${bg}`}>
      <p className="text-xs text-slate-500 mb-1">{label}</p>
      <p className={`text-2xl font-bold ${color}`}>{value}</p>
    </div>
  )
}
