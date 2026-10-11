"use client";

import { useActionState } from "react";
import { createOrganization, type FormState } from "./actions";

export function CreateOrganizationForm() {
  const [state, action, pending] = useActionState<FormState, FormData>(createOrganization, {});

  return (
    <form action={action}>
      <div className="field">
        <label htmlFor="organization-name">Organization name</label>
        <input id="organization-name" name="name" required maxLength={200} autoComplete="organization" />
      </div>
      <button className="button primary" type="submit" disabled={pending}>
        {pending ? "Creating…" : "Create organization"}
      </button>
      {state.error && (
        <p className="alert error" role="alert">
          {state.error}
        </p>
      )}
    </form>
  );
}
