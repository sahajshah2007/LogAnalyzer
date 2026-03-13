export default function TopIPs({ data = [] }) {
  const max = data[0]?.count ?? 1

  return (
    <Card title="Top Attacker IPs">
      <div className="space-y-3">
        {data.map((row) => (
          <div key={row.source_ip} className="flex items-center gap-3">
            <span className="text-sm text-slate-300 font-mono w-36 shrink-0">{row.source_ip}</span>
            <div className="flex-1 bg-slate-800 rounded-full h-2 overflow-hidden">
              <div
                className="h-2 rounded-full bg-cyan-500"
                style={{ width: `${(row.count / max) * 100}%` }}
              />
            </div>
            <span className="text-xs text-slate-400 w-16 text-right shrink-0">
              {row.count.toLocaleString()}
            </span>
          </div>
        ))}
        {data.length === 0 && (
          <p className="text-sm text-slate-500 text-center py-6">No data yet</p>
        )}
      </div>
    </Card>
  )
}

function Card({ title, children }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
      <h2 className="text-sm font-semibold text-slate-400 mb-4">{title}</h2>
      {children}
    </div>
  )
}
