-- Minimal imitation of the parts of Supabase our migrations depend on, so the
-- REAL migrations can run inside PGlite (an in-process Postgres) for testing.
-- This is NOT used on your real Supabase project: Supabase already provides all of this.
create schema if not exists extensions;
create schema if not exists auth;
create schema if not exists storage;

create role anon          nologin;
create role authenticated nologin;
create role service_role  nologin bypassrls;

create table auth.users (
  id uuid primary key default gen_random_uuid(),
  email text,
  raw_user_meta_data jsonb not null default '{}'::jsonb
);

-- Real Supabase reads the caller's id from the JWT the API gateway sets.
create function auth.uid() returns uuid language sql stable as $$
  select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid
$$;

grant usage on schema auth, public, storage, extensions to anon, authenticated, service_role;

-- Supabase's DEFAULT privileges: every new table/function in "public" is wide open to
-- anon/authenticated until you revoke it. Reproducing this proves our migrations really revoke it.
alter default privileges in schema public grant all on tables    to anon, authenticated, service_role;
alter default privileges in schema public grant all on functions to anon, authenticated, service_role;
alter default privileges in schema public grant all on sequences to anon, authenticated, service_role;

create table storage.buckets (
  id text primary key, name text not null, public boolean not null default false,
  file_size_limit bigint, allowed_mime_types text[]
);
create table storage.objects (
  id uuid primary key default gen_random_uuid(), bucket_id text not null references storage.buckets (id),
  name text not null
);
alter table storage.objects enable row level security;
grant all on storage.objects to anon, authenticated, service_role;
grant select on storage.buckets to anon, authenticated, service_role;
