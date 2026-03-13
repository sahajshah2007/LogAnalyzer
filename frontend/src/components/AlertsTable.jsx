import { useState } from 'react'
import { usePolling } from '../hooks/usePolling'
import { ChevronLeft, ChevronRight, Search, X, ChevronDown, ChevronUp } from 'lucide-react'

const SEVERITY_COLORS = {
  CRITICAL: 'bg-red-900/40 text-red-400 border border-red-800',
  WARNING:  'bg-amber-900/40 text-amber-400 border border-amber-800',
  INFO:     'bg-emerald-900/40 text-emerald-400 border border-emerald-800',
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

export default function AlertsTable() {
  const [page,      setPage]      = useState(1)
  const [severity,  setSeverity]  = useState('')
  const [eventType, setEventType] = useState('')
  const [search,    setSearch]    = useState('')
  const [searchVal, setSearchVal] = useState('')
  const [expanded,  setExpanded]  = useState(null)

  const params = new URLSearchParams({ page, limit: 20 })
  if (severity)  params.set('severity',   severity)
  if (eventType) params.set('event_type', eventType)
  if (search)    params.set('search',     search)

  const { data, loading } = usePolling(`/api/alerts?${params}`, 10000)

  function applySearch() { setSearch(searchVal); setPage(1) }
  function clearSearch()  { setSearch(''); setSearchVal(''); setPage(1) }
  function toggleExpand(id) { setExpanded(e => e === id ? null : id) }

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold text-slate-100">Alerts</h1>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="flex gap-2 flex-1 min-w-[200px]">
          <div className="relative flex-1">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              className="w-full bg-slate-800 border border-slate-700 rounded-lg px-9 py-2 text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-600"
              placeholder="Search IP, description…"
              value={searchVal}
              onChange={(e) => setSearchVal(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && applySearch()}
            />
            {searchVal && (
              <button onClick={clearSearch} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300">
                <X size={14} />
              </button>
            )}
          </div>
          <button onClick={applySearch} className="px-4 py-2 bg-cyan-700 hover:bg-cyan-600 text-white text-sm rounded-lg transition-colors">
            Search
          </button>
        </div>
        <select value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1) }}
          className="bg-slate-800 border border-slate-700 text-sm text-slate-200 rounded-lg px-3 py-2 focus:outline-none focus:border-cyan-600">
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="WARNING">Warning</option>
          <option value="INFO">Info</option>
        </select>
      </div>

      {/* Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400 text-xs uppercase">
              <th className="px-4 py-3 text-left w-6"></th>
              <th className="px-4 py-3 text-left">Timestamp</th>
              <th className="px-4 py-3 text-left">Severity</th>
              <th className="px-4 py-3 text-left">Event Type</th>
              <th className="px-4 py-3 text-left">Source IP</th>
              <th className="px-4 py-3 text-left">Description</th>
              <th className="px-4 py-3 text-left">MITRE Tactics</th>
            </tr>
          </thead>
          <tbody>
            {loading && !data ? (
              <tr><td colSpan={7} className="px-4 py-8 text-center text-slate-500">Loading…</td></tr>
            ) : data?.alerts?.length === 0 ? (
              <tr><td colSpan={7} className="px-4 py-8 text-center text-slate-500">No alerts found</td></tr>
            ) : (
              data?.alerts?.map((a) => (
                <>
                  <tr
                    key={a.id}
                    onClick={() => toggleExpand(a.id)}
                    className="border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors cursor-pointer"
                  >
                    <td className="px-3 py-2.5 text-slate-600">
                      {expanded === a.id ? <ChevronUp size={12}/> : <ChevronDown size={12}/>}
                    </td>
                    <td className="px-4 py-2.5 text-slate-400 font-mono text-xs whitespace-nowrap">{a.timestamp?.slice(0,19)}</td>
                    <td className="px-4 py-2.5">
                      <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${SEVERITY_COLORS[a.severity] ?? ''}`}>
                        {a.severity}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-slate-300 whitespace-nowrap">{a.event_type?.replace(/_/g,' ')}</td>
                    <td className="px-4 py-2.5 text-cyan-400 font-mono">{a.source_ip}</td>
                    <td className="px-4 py-2.5 text-slate-300 max-w-[280px] truncate">{a.description}</td>
                    <td className="px-4 py-2.5">
                      <div className="flex flex-wrap gap-1">
                        {Array.isArray(a.mitre_tactics) && a.mitre_tactics.map((t, i) => (
                          <span key={t} className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${tacticColor(i)}`}>{t}</span>
                        ))}
                      </div>
                    </td>
                  </tr>
                  {expanded === a.id && (
                    <tr key={`${a.id}-detail`} className="bg-slate-800/40 border-b border-slate-700">
                      <td colSpan={7} className="px-6 py-3">
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-xs">
                          <div>
                            <p className="text-slate-500 mb-1 uppercase tracking-wide font-semibold">Sigma Rule</p>
                            <p className="text-slate-300">{a.sigma_rule_title || '—'}</p>
                            {a.sigma_rule_id && <p className="text-slate-600 font-mono mt-0.5">{a.sigma_rule_id}</p>}
                          </div>
                          <div>
                            <p className="text-slate-500 mb-1 uppercase tracking-wide font-semibold">MITRE Techniques</p>
                            <div className="flex flex-wrap gap-1">
                              {Array.isArray(a.mitre_techniques) && a.mitre_techniques.length > 0
                                ? a.mitre_techniques.map(t => (
                                    <a key={t}
                                      href={`https://attack.mitre.org/techniques/${t.replace('.','/')}`}
                                      target="_blank" rel="noreferrer"
                                      className="text-cyan-400 hover:text-cyan-300 underline font-mono"
                                    >{t}</a>
                                  ))
                                : <span className="text-slate-600">—</span>
                              }
                            </div>
                          </div>
                          <div>
                            <p className="text-slate-500 mb-1 uppercase tracking-wide font-semibold">Matched Keywords</p>
                            <div className="flex flex-wrap gap-1">
                              {Array.isArray(a.matched_keywords) && a.matched_keywords.length > 0
                                ? a.matched_keywords.slice(0,6).map(k => (
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
                          {Array.isArray(a.false_positives) && a.false_positives.length > 0 && (
                            <div>
                              <p className="text-slate-500 mb-1 uppercase tracking-wide font-semibold">False Positives</p>
                              <ul className="text-slate-400 list-disc list-inside space-y-0.5">
                                {a.false_positives.map((fp, i) => <li key={i}>{fp}</li>)}
                              </ul>
                            </div>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {data && (
        <div className="flex items-center justify-between text-sm text-slate-400">
          <span>{data.total?.toLocaleString()} total alerts</span>
          <div className="flex items-center gap-2">
            <button disabled={page <= 1} onClick={() => setPage((p) => p - 1)}
              className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-30 transition">
              <ChevronLeft size={16} />
            </button>
            <span>Page {page} of {data.pages}</span>
            <button disabled={page >= data.pages} onClick={() => setPage((p) => p + 1)}
              className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-30 transition">
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
