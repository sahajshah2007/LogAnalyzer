import { ShieldAlert } from 'lucide-react'
import { usePolling } from '../hooks/usePolling'

export default function Navbar({ activeTab, onTabChange, tabs }) {
  const { data: status } = usePolling('/api/status', 6000)
  const monitoring = status?.monitoring

  return (
    <header className="sticky top-0 z-50 bg-slate-900 border-b border-slate-800 shadow-lg">
      <div className="max-w-screen-2xl mx-auto px-4 h-14 flex items-center gap-6">
        {/* Logo */}
        <div className="flex items-center gap-2 text-cyan-400 font-bold text-lg select-none shrink-0">
          <ShieldAlert size={22} />
          Log analyzer
        </div>

        {/* Status pill */}
        <span
          className={`flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full font-medium select-none ${
            monitoring
              ? 'bg-emerald-900/60 text-emerald-400 border border-emerald-700'
              : 'bg-slate-800 text-slate-400 border border-slate-700'
          }`}
        >
          <span
            className={`w-1.5 h-1.5 rounded-full ${
              monitoring ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'
            }`}
          />
          {monitoring ? 'Monitoring' : 'Idle'}
        </span>

        {/* Tabs */}
        <nav className="flex gap-1 ml-auto">
          {tabs.map((t) => (
            <button
              key={t}
              onClick={() => onTabChange(t)}
              className={`px-4 py-1.5 rounded text-sm font-medium transition-colors ${
                activeTab === t
                  ? 'bg-cyan-600 text-white'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
            >
              {t}
            </button>
          ))}
        </nav>
      </div>
    </header>
  )
}
