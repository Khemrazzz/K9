import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { getConfig } from "@/lib/config";
import { getMe } from "@/lib/k9-api";
import { cookieNames } from "@/lib/session";
import { CreateOrganizationForm } from "./create-organization-form";
import { ApiUnavailable } from "./states";

export default async function ConsoleHome() {
  const me = await getMe();
  if (!me.ok) {
    return <ApiUnavailable />;
  }

  const { organizations } = me.data;
  if (organizations.length === 0) {
    return (
      <section className="card narrow">
        <h1>Create your first organization</h1>
        <p className="muted">
          An organization holds your team and, later, your assets and findings. You will be its owner.
        </p>
        <CreateOrganizationForm />
      </section>
    );
  }

  // Resume the last organization if the user still belongs to it, otherwise the first.
  const remembered = (await cookies()).get(cookieNames(getConfig().secureCookies).organization)?.value;
  const target = organizations.find((o) => o.id === remembered) ?? organizations[0]!;
  redirect(`/app/org/${target.id}`);
}
