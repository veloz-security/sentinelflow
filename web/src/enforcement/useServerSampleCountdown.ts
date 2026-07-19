import { useEffect, useState } from 'react';

/**
 * Interpolates display time from a server-provided TTL sample. This hook never
 * changes lifecycle state or creates authority when the display reaches zero.
 */
export function useServerSampleCountdown(initialSeconds: number | null) {
  const [elapsedSeconds, setElapsedSeconds] = useState(0);

  useEffect(() => {
    if (initialSeconds === null || initialSeconds <= 0) return undefined;
    let ticks = 0;
    const timer = window.setInterval(() => {
      ticks += 1;
      setElapsedSeconds(ticks);
      if (ticks >= initialSeconds) window.clearInterval(timer);
    }, 1_000);
    return () => window.clearInterval(timer);
  }, [initialSeconds]);

  return initialSeconds === null
    ? null
    : Math.max(0, initialSeconds - elapsedSeconds);
}
