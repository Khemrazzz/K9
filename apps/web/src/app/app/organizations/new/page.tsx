import { CreateOrganizationForm } from "../../create-organization-form";

export const metadata = { title: "New organization" };

export default function NewOrganizationPage() {
  return (
    <section className="card narrow">
      <h1>New organization</h1>
      <p className="muted">You will be the owner of the new organization.</p>
      <CreateOrganizationForm />
    </section>
  );
}
