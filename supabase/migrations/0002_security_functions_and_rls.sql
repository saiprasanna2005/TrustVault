-- =====================================================================
-- 0002  Permission helper functions + Row-Level Security + privileges
-- =====================================================================

-- ---------- helper functions ----------
-- SECURITY DEFINER = runs with the owner's rights, so it can look at tables
-- the caller cannot. That is what lets RLS policies ask "does a grant exist?"
-- without causing infinite recursion between documents <-> document_grants.
-- search_path = '' forces fully-qualified names (prevents search-path hijacking).

-- Is the CALLER an administrator?
create function public.is_admin()
returns boolean
language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = (select auth.uid()) and p.role = 'admin'
  );
$$;

-- What can user X do with document Y?  'owner' | 'edit' | 'read' | null.
-- NOTE: there is intentionally NO "admin" branch. Being an admin gives no access.
-- This takes a user id, so it must never be callable by ordinary users
-- (they could probe other people's access). Only the service role may run it.
create function public.document_permission(p_document_id uuid, p_user_id uuid)
returns text
language sql stable security definer set search_path = ''
as $$
  select case
    when exists (select 1 from public.documents d
                 where d.id = p_document_id and d.owner_id = p_user_id) then 'owner'
    else (select g.permission::text from public.document_grants g
          where g.document_id = p_document_id and g.grantee_id = p_user_id)
  end;
$$;

-- Caller-only versions used inside RLS policies (they cannot be pointed at someone else).
create function public.can_read_document(p_document_id uuid)
returns boolean
language sql stable security definer set search_path = ''
as $$
  select public.document_permission(p_document_id, (select auth.uid())) is not null;
$$;

create function public.owns_document(p_document_id uuid)
returns boolean
language sql stable security definer set search_path = ''
as $$
  select public.document_permission(p_document_id, (select auth.uid())) = 'owner';
$$;

-- Supabase grants EXECUTE on new functions to anon/authenticated by default.
-- Remove that first, then hand out only what is needed.
revoke all on function public.is_admin()                           from public, anon, authenticated;
revoke all on function public.document_permission(uuid, uuid)      from public, anon, authenticated;
revoke all on function public.can_read_document(uuid)              from public, anon, authenticated;
revoke all on function public.owns_document(uuid)                  from public, anon, authenticated;

grant execute on function public.is_admin()                        to authenticated;
grant execute on function public.can_read_document(uuid)           to authenticated;
grant execute on function public.owns_document(uuid)               to authenticated;
grant execute on function public.document_permission(uuid, uuid)   to service_role;

-- ---------- table privileges ----------
-- Supabase also auto-grants ALL on new tables to anon/authenticated. Remove it.
-- Result: signed-in users can only SELECT (and only the rows RLS allows).
-- INSERT / UPDATE / DELETE are impossible from the API: every write goes through
-- an Edge Function that checks permissions and writes the audit event.
revoke all on public.profiles, public.documents, public.document_grants, public.audit_log
  from anon, authenticated;
grant select on public.profiles, public.documents, public.document_grants, public.audit_log
  to authenticated;

-- ---------- Row-Level Security ----------
alter table public.profiles        enable row level security;
alter table public.documents       enable row level security;
alter table public.document_grants enable row level security;
alter table public.audit_log       enable row level security;

-- You see your own profile; admins can list users (needed for the admin dashboard).
create policy profiles_select_self_or_admin on public.profiles
  for select to authenticated
  using (id = (select auth.uid()) or public.is_admin());

-- You see a document only if you own it or hold a grant. Admins get NO exception.
create policy documents_select_owner_or_grantee on public.documents
  for select to authenticated
  using (public.can_read_document(id));

-- You see grants that give YOU access, and every grant on documents YOU own.
create policy grants_select_owner_or_grantee on public.document_grants
  for select to authenticated
  using (grantee_id = (select auth.uid()) or public.owns_document(document_id));

-- Only administrators can read the audit log.
create policy audit_select_admin_only on public.audit_log
  for select to authenticated
  using (public.is_admin());

-- No INSERT/UPDATE/DELETE policies exist on purpose: with RLS on, "no policy" = denied.
-- (The service role used by Edge Functions bypasses RLS, which is why the
-- functions must do their own permission checks.)
