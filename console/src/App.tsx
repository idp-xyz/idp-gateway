import { FormEvent, useEffect, useState } from "react";
import { api, messageOf, type AuditRecord, type RevokedAccount } from "./api";

type View = "audit" | "revocations" | "bans";

export function App() {
  const [view, setView] = useState<View>("audit");
  return (
    <>
      <header>
        <h1>idp-gateway 控制台</h1>
        <p>只读审计，并转发已经有的撤销和封禁。这个页面不发布路由，也不回滚。</p>
      </header>
      <nav aria-label="功能">
        <ViewButton current={view} id="audit" onSelect={setView}>
          审计
        </ViewButton>
        <ViewButton current={view} id="revocations" onSelect={setView}>
          撤销
        </ViewButton>
        <ViewButton current={view} id="bans" onSelect={setView}>
          封禁
        </ViewButton>
      </nav>
      <main>
        {view === "audit" ? <AuditPanel /> : null}
        {view === "revocations" ? <RevocationPanel /> : null}
        {view === "bans" ? <BanPanel /> : null}
      </main>
    </>
  );
}

function ViewButton({
  current,
  id,
  onSelect,
  children,
}: {
  current: View;
  id: View;
  onSelect: (view: View) => void;
  children: string;
}) {
  return (
    <button type="button" aria-current={current === id ? "page" : undefined} onClick={() => onSelect(id)}>
      {children}
    </button>
  );
}

function AuditPanel() {
  const [traceID, setTraceID] = useState("");
  const [decisionID, setDecisionID] = useState("");
  const [outcome, setOutcome] = useState("");
  const [limit, setLimit] = useState("50");
  const [records, setRecords] = useState<AuditRecord[] | null>(null);
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  async function load(event?: FormEvent) {
    event?.preventDefault();
    setBusy(true);
    const query = new URLSearchParams({ limit });
    if (traceID) query.set("trace_id", traceID);
    if (decisionID) query.set("decision_id", decisionID);
    if (outcome) query.set("outcome", outcome);
    const result = await api(`/v1/audit?${query.toString()}`);
    setBusy(false);
    if (result.status === 200 && result.body.records) {
      setRecords(result.body.records);
      setNotice(result.body.records.length === 0 ? "没有符合条件的记录" : `${result.body.records.length} 条`);
      return;
    }
    setRecords(null);
    setNotice(messageOf(result));
  }

  useEffect(() => {
    void load();
  }, []);

  return (
    <section aria-labelledby="audit-heading">
      <h2 id="audit-heading">审计</h2>
      <form onSubmit={(event) => void load(event)}>
        <label htmlFor="trace-id">trace id</label>
        <input id="trace-id" value={traceID} onChange={(event) => setTraceID(event.target.value)} />
        <label htmlFor="decision-id">判定编号</label>
        <input id="decision-id" value={decisionID} onChange={(event) => setDecisionID(event.target.value)} />
        <label htmlFor="outcome">结果</label>
        <input id="outcome" value={outcome} onChange={(event) => setOutcome(event.target.value)} />
        <label htmlFor="limit">条数</label>
        <select id="limit" value={limit} onChange={(event) => setLimit(event.target.value)}>
          <option value="20">20</option>
          <option value="50">50</option>
          <option value="100">100</option>
          <option value="200">200</option>
        </select>
        <button type="submit" disabled={busy}>
          查询
        </button>
      </form>
      <p role="status">{notice}</p>
      <AuditTable records={records} />
    </section>
  );
}

function AuditTable({ records }: { records: AuditRecord[] | null }) {
  if (!records || records.length === 0) {
    return null;
  }
  return (
    <table>
      <caption>最近的审计记录，新的在前</caption>
      <thead>
        <tr>
          <th scope="col">时间</th>
          <th scope="col">结果</th>
          <th scope="col">trace id</th>
          <th scope="col">判定编号</th>
          <th scope="col">账户</th>
          <th scope="col">操作</th>
        </tr>
      </thead>
      <tbody>
        {records.map((record, index) => (
          <tr key={`${record.timestamp ?? ""}-${record.decision_id ?? ""}-${index}`}>
            <td data-label="时间">{record.timestamp}</td>
            <td data-label="结果">{record.outcome}</td>
            <td data-label="trace id">{record.trace_id}</td>
            <td data-label="判定编号">{record.decision_id}</td>
            <td data-label="账户">{record.account}</td>
            <td data-label="操作">{record.operation_id}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function RevocationPanel() {
  const [account, setAccount] = useState("");
  const [reason, setReason] = useState("");
  const [rows, setRows] = useState<RevokedAccount[] | null>(null);
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  async function refresh() {
    const result = await api("/v1/revocations");
    if (result.status === 200 && result.body.revoked_accounts) {
      setRows(result.body.revoked_accounts);
      return;
    }
    setRows(null);
    if (result.status !== 200) {
      setNotice(messageOf(result));
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const submitter = (event.nativeEvent as SubmitEvent).submitter;
    const action = submitter instanceof HTMLButtonElement ? submitter.value : "";
    if (!account.trim()) {
      setNotice("要填写账户");
      return;
    }
    if (action === "revoke" && !reason.trim()) {
      setNotice("撤销要填写原因");
      return;
    }
    setBusy(true);
    const result = await api("/v1/revocations", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        account_id: account.trim(),
        revoked: action === "revoke",
        ...(action === "revoke" ? { reason: reason.trim() } : {}),
      }),
    });
    setBusy(false);
    setNotice(messageOf(result));
    if (result.status === 200) {
      await refresh();
    }
  }

  return (
    <section aria-labelledby="revocation-heading">
      <h2 id="revocation-heading">撤销</h2>
      <form onSubmit={(event) => void submit(event)}>
        <label htmlFor="account-id">账户</label>
        <input id="account-id" value={account} maxLength={256} onChange={(event) => setAccount(event.target.value)} required />
        <label htmlFor="revoke-reason">原因</label>
        <input id="revoke-reason" value={reason} maxLength={512} onChange={(event) => setReason(event.target.value)} />
        <button type="submit" name="revoke" value="revoke" disabled={busy}>
          撤销
        </button>
        <button type="submit" name="restore" value="restore" disabled={busy}>
          恢复
        </button>
      </form>
      <p role="status">{notice}</p>
      <AccountTable rows={rows} />
    </section>
  );
}

function AccountTable({ rows }: { rows: RevokedAccount[] | null }) {
  if (!rows) {
    return null;
  }
  if (rows.length === 0) {
    return <p>撤销表是空的</p>;
  }
  return (
    <table>
      <caption>当前被撤销的账户</caption>
      <thead>
        <tr>
          <th scope="col">账户</th>
          <th scope="col">时间</th>
          <th scope="col">撤销者</th>
          <th scope="col">原因</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr key={row.account_id}>
            <td data-label="账户">{row.account_id}</td>
            <td data-label="时间">{row.revoked_at}</td>
            <td data-label="撤销者">{row.revoked_by}</td>
            <td data-label="原因">{row.reason}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function BanPanel() {
  const [operation, setOperation] = useState("");
  const [reason, setReason] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const submitter = (event.nativeEvent as SubmitEvent).submitter;
    const action = submitter instanceof HTMLButtonElement ? submitter.value : "";
    if (!operation.trim()) {
      setNotice("要填写操作");
      return;
    }
    if (action === "ban" && !reason.trim()) {
      setNotice("封禁要填写原因");
      return;
    }
    setBusy(true);
    const result = await api("/v1/operation-bans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        operation_id: operation.trim(),
        banned: action === "ban",
        ...(action === "ban" ? { reason: reason.trim() } : {}),
      }),
    });
    setBusy(false);
    setNotice(messageOf(result));
  }

  return (
    <section aria-labelledby="ban-heading">
      <h2 id="ban-heading">封禁</h2>
      <form onSubmit={(event) => void submit(event)}>
        <label htmlFor="operation-id">操作</label>
        <input id="operation-id" value={operation} maxLength={256} onChange={(event) => setOperation(event.target.value)} required />
        <label htmlFor="ban-reason">原因</label>
        <input id="ban-reason" value={reason} maxLength={512} onChange={(event) => setReason(event.target.value)} />
        <button type="submit" value="ban" disabled={busy}>
          封禁
        </button>
        <button type="submit" value="unban" disabled={busy}>
          解除封禁
        </button>
      </form>
      <p role="status">{notice}</p>
    </section>
  );
}
