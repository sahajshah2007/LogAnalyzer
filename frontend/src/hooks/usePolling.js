import { useState, useEffect, useRef, useCallback } from 'react'

/**
 * Poll an API endpoint at a fixed interval.
 * @param {string} url
 * @param {number} interval  ms between polls (default 5000)
 */
export function usePolling(url, interval = 5000) {
  const [data, setData]       = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)
  const timerRef              = useRef(null)

  const fetchData = useCallback(async () => {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 5000)
    try {
      const res = await fetch(url, { signal: controller.signal })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      setData(await res.json())
      setError(null)
    } catch (e) {
      if (e.name === 'AbortError') {
        setError('Request timed out — is the API server running?')
      } else {
        setError(e.message)
      }
    } finally {
      clearTimeout(timeout)
      setLoading(false)
    }
  }, [url])

  useEffect(() => {
    fetchData()
    timerRef.current = setInterval(fetchData, interval)
    return () => clearInterval(timerRef.current)
  }, [fetchData, interval])

  return { data, loading, error, refetch: fetchData }
}
