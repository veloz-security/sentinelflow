export function shortDigest(value: string) {
  if (!value.startsWith('sha256:') || value.length < 24) {
    return value;
  }
  return `${value.slice(0, 15)}…${value.slice(-8)}`;
}

export function formatUtc(value: string) {
  return new Intl.DateTimeFormat('en', {
    dateStyle: 'medium',
    timeStyle: 'short',
    timeZone: 'UTC',
  }).format(new Date(value));
}

export function humanizeIdentifier(value: string) {
  return value.replaceAll('_', ' ').replaceAll('.', ' · ');
}

export function shortIdentifier(value: string) {
  return value.length > 18 ? `${value.slice(0, 8)}…${value.slice(-6)}` : value;
}
