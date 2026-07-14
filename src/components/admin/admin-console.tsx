"use client";

import { FormEvent, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";

import { SignOutButton } from "@/components/auth/sign-out-button";
import { BrandMark } from "@/components/brand-mark";
import { SocialIcon } from "@/components/social-icon";
import type {
  AdminConnector,
  AdminUser,
  PendingInvitation,
} from "@/lib/admin-users";

export function AdminConsole({
  invitations,
  operatorId,
  users,
}: {
  invitations: PendingInvitation[];
  operatorId: string;
  users: AdminUser[];
}) {
  const router = useRouter();
  const [query, setQuery] = useState("");
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null);
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [messageType, setMessageType] = useState<"error" | "success">("success");

  const filteredUsers = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return users;
    return users.filter((user) =>
      [user.name, user.email, user.username ?? ""]
        .some((value) => value.toLowerCase().includes(normalized)),
    );
  }, [query, users]);
  const selectedUser = users.find((user) => user.id === selectedUserId);
  const connectedCount = users.reduce(
    (total, user) => total + user.connectors.filter((connector) => connector.connected).length,
    0,
  );

  async function requestAction(
    key: string,
    url: string,
    options: RequestInit,
    successMessage: string,
  ) {
    setPendingAction(key);
    setMessage(null);
    try {
      const response = await fetch(url, {
        ...options,
        headers: {
          "Content-Type": "application/json",
          ...options.headers,
        },
      });
      const result = await response.json() as { error?: string };
      if (!response.ok) throw new Error(result.error || "The request could not be completed.");
      setMessage(successMessage);
      setMessageType("success");
      router.refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The request could not be completed.");
      setMessageType("error");
    } finally {
      setPendingAction(null);
    }
  }

  async function handleInvite(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const email = String(new FormData(form).get("email") ?? "").trim();
    await requestAction(
      "invite",
      "/api/admin/invitations",
      { method: "POST", body: JSON.stringify({ email }) },
      `Invitation sent to ${email}.`,
    );
    form.reset();
  }

  function updateUser(user: AdminUser, action: Record<string, unknown>, label: string) {
    return requestAction(
      `${user.id}:${String(action.action)}`,
      `/api/admin/users/${encodeURIComponent(user.id)}`,
      { method: "POST", body: JSON.stringify(action) },
      label,
    );
  }

  function disconnectConnector(user: AdminUser, connector: AdminConnector) {
    if (!window.confirm(
      `Disconnect ${connector.label} for ${user.email}? Their active sessions will also be revoked.`,
    )) return;

    void requestAction(
      `${user.id}:disconnect:${connector.provider}`,
      `/api/admin/users/${encodeURIComponent(user.id)}/connectors/${connector.provider}`,
      { method: "DELETE" },
      `${connector.label} disconnected for ${user.email}.`,
    );
  }

  return (
    <main className="admin-shell">
      <header className="admin-header">
        <BrandMark compact />
        <div className="admin-header__title">
          <p className="eyebrow eyebrow--green">INTERNAL / PORTLAND</p>
          <h1>Identity administration</h1>
        </div>
        <Link className="admin-header__evidence" href="/owner">Company workflows</Link>
        <Link className="admin-header__evidence" href="/admin/evidence">First-slice tools</Link>
        <SignOutButton />
      </header>

      <section className="admin-overview" aria-label="Identity overview">
        <AdminMetric label="Users" value={users.length} detail={`${users.filter((user) => user.active).length} active`} />
        <AdminMetric label="Connected identities" value={connectedCount} detail="Across five providers" />
        <AdminMetric label="Pending invitations" value={invitations.length} detail="Valid invitations" />
      </section>

      <section className="admin-invite" aria-labelledby="invite-title">
        <div>
          <p className="eyebrow eyebrow--green">ONBOARDING</p>
          <h2 id="invite-title">Invite a user</h2>
          <p>V·Sign will recommend the email domain’s SSO provider before showing the manual-password path.</p>
        </div>
        <form onSubmit={handleInvite}>
          <label className="field">
            <span>Email address</span>
            <input name="email" type="email" required placeholder="new.user@company.com" />
          </label>
          <button className="primary-button" type="submit" disabled={pendingAction === "invite"}>
            <span>{pendingAction === "invite" ? "Sending…" : "Send invitation"}</span>
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h14M14 7l5 5-5 5" /></svg>
          </button>
        </form>
      </section>

      {invitations.length > 0 && (
        <section className="pending-invitations" aria-label="Pending invitations">
          {invitations.map((invitation) => (
            <span key={invitation.id}>
              <strong>{invitation.email}</strong>
              expires {new Date(invitation.expiresAt).toLocaleDateString()}
            </span>
          ))}
        </section>
      )}

      {message && (
        <p className={`admin-message admin-message--${messageType}`} role="status">
          {message}
        </p>
      )}

      <section className="admin-users" aria-labelledby="users-title">
        <div className="admin-users__toolbar">
          <div>
            <p className="eyebrow eyebrow--green">DIRECTORY</p>
            <h2 id="users-title">Login portal users</h2>
          </div>
          <label className="admin-search">
            <span className="sr-only">Search users</span>
            <input value={query} onChange={(event) => setQuery(event.target.value)} type="search" placeholder="Search name, email, or username" />
          </label>
        </div>

        <div className="connector-legend" aria-label="Connector status legend">
          <StatusLegend status="active" label="Active" />
          <StatusLegend status="stale" label="No login for 90+ days" />
          <StatusLegend status="error" label="Connection problem" />
          <StatusLegend status="disconnected" label="Not connected" />
        </div>

        <div className="admin-table-wrap">
          <table className="admin-table">
            <thead>
              <tr>
                <th>User</th>
                <th>Connectors</th>
                <th>Username / password</th>
                <th>Account</th>
                <th><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {filteredUsers.map((user) => {
                const isOperator = user.id === operatorId;
                const userPending = pendingAction?.startsWith(`${user.id}:`) ?? false;
                return (
                  <tr key={user.id}>
                    <td>
                      <span className="admin-user-name">{user.name}</span>
                      <span className="admin-user-email">{user.email}</span>
                      <span className="admin-user-meta">{user.username ? `@${user.username}` : "No username"}{user.role.includes("admin") ? " · Admin" : ""}</span>
                    </td>
                    <td>
                      <div className="connector-chips">
                        {user.connectors.map((connector) => (
                          <span className={`connector-chip connector-chip--${connector.status}`} key={connector.provider} title={connectorTitle(connector)}>
                            <i aria-hidden="true" />
                            {connector.label}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td>
                      <label className="password-option">
                        <input
                          type="checkbox"
                          checked={user.manualPassword}
                          disabled={userPending || isOperator}
                          onChange={(event) => {
                            const enabled = event.target.checked;
                            const prompt = enabled
                              ? `Enable a manual password for ${user.email} and send a setup link?`
                              : `Disable manual password sign-in for ${user.email}? Their sessions will be revoked.`;
                            if (window.confirm(prompt)) {
                              void updateUser(user, { action: "set-password", enabled }, enabled ? "Password setup link sent." : "Manual password disabled.");
                            }
                          }}
                        />
                        <span>{user.manualPassword ? "Enabled" : "Disabled"}</span>
                      </label>
                      <button
                        className="table-link"
                        type="button"
                        disabled={!user.manualPassword || userPending}
                        onClick={() => void updateUser(user, { action: "reset-password" }, `Password reset sent to ${user.email}.`)}
                      >
                        Reset password
                      </button>
                    </td>
                    <td>
                      <button
                        className={`account-switch ${user.active ? "account-switch--active" : ""}`}
                        role="switch"
                        aria-checked={user.active}
                        type="button"
                        disabled={userPending || isOperator}
                        onClick={() => {
                          const enabled = !user.active;
                          if (enabled || window.confirm(`Disable ${user.email} and revoke all sessions?`)) {
                            void updateUser(user, { action: "set-active", enabled }, enabled ? "User enabled." : "User disabled.");
                          }
                        }}
                      >
                        <i aria-hidden="true" />
                        <span>{user.active ? "Active" : "Disabled"}</span>
                      </button>
                    </td>
                    <td>
                      <button className="secondary-button" type="button" onClick={() => setSelectedUserId(user.id)}>
                        Manage connectors
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      {selectedUser && (
        <div className="connector-modal" role="presentation" onMouseDown={(event) => {
          if (event.currentTarget === event.target) setSelectedUserId(null);
        }}>
          <section role="dialog" aria-modal="true" aria-labelledby="connector-dialog-title">
            <button className="connector-modal__close" type="button" aria-label="Close connector manager" onClick={() => setSelectedUserId(null)}>×</button>
            <p className="eyebrow eyebrow--green">IDENTITY CONNECTIONS</p>
            <h2 id="connector-dialog-title">Manage connectors</h2>
            <p className="connector-modal__user">{selectedUser.name} · {selectedUser.email}</p>
            <p className="connector-modal__explanation">
              A connector links V·Sign to an identity held by Microsoft, Google, Apple, Yahoo, or Zoho. Force disconnect removes the V·Sign link and revokes V·Sign sessions; it does not delete the user’s provider account.
            </p>
            <div className="connector-modal__list">
              {selectedUser.connectors.map((connector) => (
                <article key={connector.provider}>
                  <SocialIcon provider={connector.provider} />
                  <div>
                    <strong><i className={`connector-status connector-status--${connector.status}`} aria-hidden="true" />{connector.label}</strong>
                    <span>{connectorDescription(connector)}</span>
                  </div>
                  <button
                    className="danger-button"
                    type="button"
                    disabled={!connector.connected || selectedUser.id === operatorId || pendingAction !== null}
                    onClick={() => disconnectConnector(selectedUser, connector)}
                  >
                    Force disconnect
                  </button>
                </article>
              ))}
            </div>
          </section>
        </div>
      )}
    </main>
  );
}

function AdminMetric({ detail, label, value }: { detail: string; label: string; value: number }) {
  return <article><span>{label}</span><strong>{value}</strong><small>{detail}</small></article>;
}

function StatusLegend({ label, status }: { label: string; status: AdminConnector["status"] }) {
  return <span><i className={`connector-status connector-status--${status}`} aria-hidden="true" />{label}</span>;
}

function connectorTitle(connector: AdminConnector) {
  return `${connector.label}: ${connectorDescription(connector)}`;
}

function connectorDescription(connector: AdminConnector) {
  if (connector.status === "disconnected") return "Not connected";
  if (connector.status === "error") return "Previously connected, but the provider is unavailable or the link is invalid";
  if (connector.status === "stale") {
    return `Connected; last authentication ${connector.lastAuthenticatedAt ? new Date(connector.lastAuthenticatedAt).toLocaleDateString() : "more than 90 days ago"}`;
  }
  return `Active${connector.lastAuthenticatedAt ? `; last authentication ${new Date(connector.lastAuthenticatedAt).toLocaleDateString()}` : ""}`;
}
