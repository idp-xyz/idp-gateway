export type AuditRecord = {
  timestamp?: string;
  service?: string;
  event_type?: string;
  trace_id?: string;
  decision_id?: string;
  outcome?: string;
  reason?: string;
  account?: string;
  operation_id?: string;
  tenant?: string;
  path?: string;
  status?: number;
  duration_ms?: number;
};

export type RevokedAccount = {
  account_id: string;
  revoked_at: string;
  revoked_by: string;
  reason: string;
};

export type ApiBody = {
  records?: AuditRecord[];
  error?: string;
  outcome?: string;
  http_status?: number;
  account_id?: string;
  operation_id?: string;
  revoked?: boolean;
  banned?: boolean;
  changed?: boolean;
  revocation_epoch?: number;
  revoked_accounts?: RevokedAccount[];
};

export type ApiResult = { status: number; body: ApiBody };

export async function api(path: string, init?: RequestInit): Promise<ApiResult> {
  const response = await fetch(path, {
    ...init,
    headers: { Accept: "application/json", ...init?.headers },
  });
  const text = await response.text();
  let body: ApiBody = {};
  if (text) {
    try {
      body = JSON.parse(text) as ApiBody;
    } catch {
      body = { error: text.trim() };
    }
  }
  return { status: response.status, body };
}

export function messageOf(result: ApiResult): string {
  if (result.body.error) {
    return result.body.error;
  }
  if (result.body.outcome) {
    const changed = result.body.changed === undefined ? "" : result.body.changed ? "，已改变" : "，本来就是这个状态";
    return `${result.body.outcome}${changed}`;
  }
  return `HTTP ${result.status}`;
}
