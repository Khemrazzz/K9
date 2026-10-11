"use client";

import { useParams } from "next/navigation";
import { selectOrganization } from "./actions";

type Option = { id: string; name: string; role: string };

/**
 * Lists the organizations the API says the user belongs to. Choosing one asks the server
 * to switch; the server re-checks membership and the API authorizes every page load.
 */
export function OrganizationSwitcher({ organizations }: { organizations: Option[] }) {
  const params = useParams<{ organizationId?: string }>();
  const current = organizations.find((o) => o.id === params.organizationId)?.id ?? "";

  return (
    <form className="switcher" action={selectOrganization}>
      <label className="visually-hidden" htmlFor="organization-switcher">
        Organization
      </label>
      <select
        id="organization-switcher"
        name="organizationId"
        key={current}
        defaultValue={current}
        onChange={(event) => {
          const form = event.currentTarget.form;
          form?.requestSubmit();
        }}
      >
        {current === "" && (
          <option value="" disabled>
            Select organization…
          </option>
        )}
        {organizations.map((organization) => (
          <option key={organization.id} value={organization.id}>
            {organization.name} ({organization.role})
          </option>
        ))}
      </select>
      <noscript>
        <button className="button" type="submit">
          Switch
        </button>
      </noscript>
    </form>
  );
}
