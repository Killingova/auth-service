type Labels = Record<string, string | number | boolean | undefined>;

type HistogramBucket = {
  le: number;
  count: number;
};

type HistogramState = {
  count: number;
  sum: number;
  buckets: HistogramBucket[];
};

const counters = new Map<string, number>();
const histograms = new Map<string, HistogramState>();

const REQUEST_DURATION_BUCKETS = [
  0.005,
  0.01,
  0.025,
  0.05,
  0.1,
  0.25,
  0.5,
  1,
  2.5,
  5,
  10,
];

function escapeLabel(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/\"/g, '\\\"').replace(/\n/g, "\\n");
}

function labelKey(labels?: Labels): string {
  if (!labels) return "";

  const parts = Object.entries(labels)
    .filter(([, value]) => value !== undefined)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${String(v)}`);

  return parts.join(",");
}

function labelText(labels?: Labels): string {
  if (!labels) return "";

  const parts = Object.entries(labels)
    .filter(([, value]) => value !== undefined)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=\"${escapeLabel(String(v))}\"`);

  if (parts.length === 0) return "";
  return `{${parts.join(",")}}`;
}

function counterKey(name: string, labels?: Labels): string {
  const key = labelKey(labels);
  return key ? `${name}|${key}` : name;
}

function histogramKey(name: string, labels?: Labels): string {
  const key = labelKey(labels);
  return key ? `${name}|${key}` : name;
}

export function incCounter(name: string, labels?: Labels, by = 1) {
  const key = counterKey(name, labels);
  counters.set(key, (counters.get(key) ?? 0) + by);
}

export function observeHistogram(
  name: string,
  value: number,
  labels?: Labels,
  buckets: number[] = REQUEST_DURATION_BUCKETS,
) {
  const key = histogramKey(name, labels);

  let state = histograms.get(key);
  if (!state) {
    state = {
      count: 0,
      sum: 0,
      buckets: buckets.map((le) => ({ le, count: 0 })),
    };
    histograms.set(key, state);
  }

  state.count += 1;
  state.sum += value;

  for (const bucket of state.buckets) {
    if (value <= bucket.le) {
      bucket.count += 1;
    }
  }
}

export function recordHttpRequest(
  method: string,
  route: string,
  statusCode: number,
  durationSeconds: number,
) {
  const labels = {
    method,
    route,
    status: statusCode,
  };

  incCounter("http_requests_total", labels, 1);
  observeHistogram("http_request_duration_seconds", durationSeconds, { method, route });
}

export function recordAuthLogin(success: boolean) {
  incCounter(success ? "auth_login_success_total" : "auth_login_failed_total", undefined, 1);
}

export function recordAuthRefreshSuccess() {
  incCounter("auth_refresh_success_total", undefined, 1);
}

export function recordAuthRefreshReuseDetected() {
  incCounter("auth_refresh_reuse_detected_total", undefined, 1);
}

function parseCounterKey(key: string): { name: string; labels?: Labels } {
  const [name, raw] = key.split("|", 2);
  if (!raw) return { name };

  const labels: Labels = {};
  for (const part of raw.split(",")) {
    const [k, v] = part.split("=", 2);
    labels[k] = v;
  }
  return { name, labels };
}

function parseHistogramKey(key: string): { name: string; labels?: Labels } {
  return parseCounterKey(key);
}

export function renderPrometheusMetrics(): string {
  const lines: string[] = [];

  lines.push("# HELP http_requests_total Total number of HTTP requests");
  lines.push("# TYPE http_requests_total counter");

  for (const [key, value] of counters.entries()) {
    const { name, labels } = parseCounterKey(key);
    lines.push(`${name}${labelText(labels)} ${value}`);
  }

  lines.push("# HELP http_request_duration_seconds HTTP request duration in seconds");
  lines.push("# TYPE http_request_duration_seconds histogram");

  for (const [key, state] of histograms.entries()) {
    const { name, labels } = parseHistogramKey(key);

    for (const bucket of state.buckets) {
      const bucketLabels: Labels = {
        ...(labels ?? {}),
        le: bucket.le,
      };
      lines.push(`${name}_bucket${labelText(bucketLabels)} ${bucket.count}`);
    }

    const infLabels: Labels = {
      ...(labels ?? {}),
      le: "+Inf",
    };
    lines.push(`${name}_bucket${labelText(infLabels)} ${state.count}`);
    lines.push(`${name}_sum${labelText(labels)} ${state.sum}`);
    lines.push(`${name}_count${labelText(labels)} ${state.count}`);
  }

  if (lines.length === 0) {
    return "\n";
  }

  return `${lines.join("\n")}\n`;
}
