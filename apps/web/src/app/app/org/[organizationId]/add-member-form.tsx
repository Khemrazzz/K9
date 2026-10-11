"use client";

import { useActionState } from "react";
import { addMember, type FormState } from "../../actions";

export function AddMemberForm({ organizationId, roles }: { organizationId: string; roles: readonly string[] }) {
  const [state, action, pending] = useActionState<FormState, FormData>(addMember.bind(null, organizationId), {});

  return (
    <form action={action}>
      <div className="inline-form">
        <div className="field">
          <label htmlFor="member-email">Email</label>
          <input id="member-email" name="email" type="email" required autoComplete="off" />
        </div>
        <div className="field">
          <label htmlFor="member-role">Role</label>
          <select id="member-role" name="role" defaultValue="Viewer">
            {roles.map((role) => (
              <option key={role} value={role}>
                {role}
              </option>
            ))}
          </select>
        </div>
        <button className="button primary" type="submit" disabled={pending}>
          {pending ? "Adding…" : "Add member"}
        </button>
      </div>
      {state.error && (
        <p className="alert error" role="alert">
          {state.error}
        </p>
      )}
      {state.success && (
        <p className="alert success" role="status">
          {state.success}
        </p>
      )}
    </form>
  );
}
