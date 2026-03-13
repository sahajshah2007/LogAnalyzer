import { useState } from 'react'
import { Play, Square, Loader2 } from 'lucide-react'
import { usePolling } from '../hooks/usePolling'

export default function MonitorControl() {
  const { data: status, refetch } = usePolling('/api/status', 5000)
  const [busy, setBusy] = useState(false)

  const monitoring = status?.monitoring

  async function toggle() {
    setBusy(true)
    const endpoint = monitoring ? '/api/control/stop' : '/api/control/start'
    try {
      await fetch(endpoint, { method: 'POST' })
      await refetch()
    } finally {
      setBusy(false)
    }
  }

  return (
    <button
      onClick={toggle}
      disabled={busy}
      className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors disabled:opacity-50 ${
        monitoring
          ? 'bg-red-600/20 border border-red-700 text-red-400 hover:bg-red-600/30'
          : 'bg-emerald-600/20 border border-emerald-700 text-emerald-400 hover:bg-emerald-600/30'
      }`}
    >
      {busy ? (
        <Loader2 size={15} className="animate-spin" />
      ) : monitoring ? (
        <Square size={15} />
      ) : (
        <Play size={15} />
      )}
      {monitoring ? 'Stop Monitor' : 'Start Monitor'}
    </button>
  )
}
