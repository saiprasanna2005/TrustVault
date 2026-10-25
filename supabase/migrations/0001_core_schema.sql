-- =====================================================================
-- 0001  Core tables
-- Plain English: this creates the four tables TrustVault needs:
--   profiles        one row per user (holds the ROLE: admin / owner / viewer)
--   documents       metadata about each uploaded file (the file itself is in Storage)
--   document_grants "user X may read/edit document Y" records
--   audit_log       append-only record of security-relevant events
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

create type public.app_role as enum ('admin', 'owner', 'viewer');
create type public.grant_permission as enum ('read', 'edit');

-- ---------- profiles ----------
create table public.profiles (
  id         uuid primary key references auth.users (id) on delete cascade,
  email      text not null,
  role       public.app_role not null default 'owner',
  created_at timestamptz not null default now()
);
create unique index profiles_email_lower_idx on public.profiles (lower(email));

-- Every new auth user automatically gets a profile. The role is HARD-CODED to
-- 'owner': nothing the user sends at signup (metadata) can choose the role.
create function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, email, role)
  values (new.id, lower(new.email), 'owner');
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Second line of defence against self-promotion: even if someone later grants
-- UPDATE on profiles by mistake, a signed-in user (auth.uid() is not null)
-- still cannot change role/email/id. Admins are created from the SQL editor,
-- where auth.uid() is null.
create function public.profiles_block_identity_change()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if (new.role is distinct from old.role
      or new.email is distinct from old.email
      or new.id is distinct from old.id)
     and (select auth.uid()) is not null then
    raise exception 'role, email and id cannot be changed through the API'
      using errcode = '42501';
  end if;
  return new;
end;
$$;

create trigger profiles_block_identity_change
  before update on public.profiles
  for each row execute function public.profiles_block_identity_change();

-- ---------- documents ----------
create table public.documents (
  id                uuid primary key default gen_random_uuid(),
  owner_id          uuid not null references public.profiles (id) on delete cascade,
  owner_email       text not null,
  title             text not null check (char_length(title) between 1 and 200),
  description       text not null default '' check (char_length(description) <= 2000),
  original_filename text not null check (char_length(original_filename) between 1 and 255),
  mime_type         text not null check (mime_type in ('application/pdf', 'image/png', 'image/jpeg')),
  size_bytes        integer not null check (size_bytes > 0 and size_bytes <= 5242880),
  sha256            text not null check (sha256 ~ '^[0-9a-f]{64}$'),
  storage_path      text not null unique,
  created_at        timestamptz not null default now(),
  updated_at        timestamptz not null default now()
);
create index documents_owner_idx on public.documents (owner_id);

-- Only title and description may ever change. Everything else (owner, file
-- type, size, hash, storage path) is frozen, even for the service role.
create function public.documents_protect_immutable()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if new.id is distinct from old.id
     or new.owner_id is distinct from old.owner_id
     or new.owner_email is distinct from old.owner_email
     or new.original_filename is distinct from old.original_filename
     or new.mime_type is distinct from old.mime_type
     or new.size_bytes is distinct from old.size_bytes
     or new.sha256 is distinct from old.sha256
     or new.storage_path is distinct from old.storage_path
     or new.created_at is distinct from old.created_at then
    raise exception 'only title and description can be edited' using errcode = '42501';
  end if;
  return new;
end;
$$;

create trigger documents_protect_immutable
  before update on public.documents
  for each row execute function public.documents_protect_immutable();

-- ---------- document_grants ----------
create table public.document_grants (
  id          uuid primary key default gen_random_uuid(),
  document_id uuid not null references public.documents (id) on delete cascade,
  grantee_id  uuid not null references public.profiles (id) on delete cascade,
  permission  public.grant_permission not null,
  granted_by  uuid not null references public.profiles (id) on delete cascade,
  created_at  timestamptz not null default now(),
  unique (document_id, grantee_id)
);
create index document_grants_grantee_idx on public.document_grants (grantee_id);

-- ---------- audit_log ----------
create table public.audit_log (
  id             bigint generated always as identity primary key,
  created_at     timestamptz not null default now(),
  request_id     uuid not null,
  actor_id       uuid,           -- null when the caller was not authenticated
  actor_email    text,
  action         text not null check (action in (
                   'document.upload', 'document.read', 'document.download',
                   'document.edit', 'document.delete',
                   'permission.grant', 'permission.revoke')),
  outcome        text not null check (outcome in ('success', 'denied', 'failure')),
  document_id    uuid,           -- deliberately NO foreign key: log must outlive the document
  target_user_id uuid,
  details        jsonb not null default '{}'::jsonb,
  prev_hash      text not null,
  row_hash       text not null
);
create index audit_log_chain_idx on public.audit_log (created_at, id);
create index audit_log_action_idx on public.audit_log (action, outcome);
