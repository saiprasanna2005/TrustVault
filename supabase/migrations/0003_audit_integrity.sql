-- =====================================================================
-- 0003  Audit log: append-only + hash chain (tamper EVIDENCE, not tamper PROOF)
-- =====================================================================

-- Hash of one row = SHA-256( previous row's hash | this row's fields ).
-- Changing or deleting any old row breaks every hash after it.
create function public.compute_audit_hash(r public.audit_log)
returns text
language sql stable set search_path = ''
as $$
  select encode(
    extensions.digest(
      convert_to(concat_ws('|',
        r.prev_hash,
        extract(epoch from r.created_at)::text,
        r.request_id::text,
        coalesce(r.actor_id::text, ''),
        coalesce(r.actor_email, ''),
        r.action,
        r.outcome,
        coalesce(r.document_id::text, ''),
        coalesce(r.target_user_id::text, ''),
        r.details::text
      ), 'UTF8'),
      'sha256'),
    'hex');
$$;

-- Runs inside the database on every insert, so the Edge Function cannot forget
-- (or fake) the hash or the timestamp. The advisory lock makes concurrent inserts
-- line up one after another so the chain has a single order.
create function public.audit_log_chain()
returns trigger
language plpgsql security definer set search_path = ''
as $$
declare
  v_prev text;
begin
  perform pg_advisory_xact_lock(hashtext('trustvault_audit_chain'));
  select a.row_hash into v_prev
    from public.audit_log a
    order by a.created_at desc, a.id desc
    limit 1;
  new.prev_hash  := coalesce(v_prev, repeat('0', 64));
  new.created_at := clock_timestamp();
  new.row_hash   := public.compute_audit_hash(new);
  return new;
end;
$$;

create trigger audit_log_chain
  before insert on public.audit_log
  for each row execute function public.audit_log_chain();

-- Append-only: UPDATE, DELETE and TRUNCATE are rejected for EVERYONE,
-- including the service role. (A database owner could drop the trigger: see THREATS.md.)
create function public.audit_log_block_mutation()
returns trigger
language plpgsql set search_path = ''
as $$
begin
  raise exception 'audit_log is append-only' using errcode = '42501';
end;
$$;

create trigger audit_log_no_update_delete
  before update or delete on public.audit_log
  for each row execute function public.audit_log_block_mutation();

create trigger audit_log_no_truncate
  before truncate on public.audit_log
  for each statement execute function public.audit_log_block_mutation();

-- Re-computes the whole chain. Admin only. Returns where it first breaks (if it does).
create function public.verify_audit_chain()
returns table (valid boolean, checked bigint, first_bad_id bigint)
language plpgsql stable security definer set search_path = ''
as $$
declare
  r        public.audit_log;
  v_prev   text := repeat('0', 64);
  v_count  bigint := 0;
begin
  if not public.is_admin() then
    raise exception 'not authorised' using errcode = '42501';
  end if;

  for r in select * from public.audit_log a order by a.created_at, a.id loop
    v_count := v_count + 1;
    if r.prev_hash <> v_prev or r.row_hash <> public.compute_audit_hash(r) then
      return query select false, v_count, r.id;
      return;
    end if;
    v_prev := r.row_hash;
  end loop;

  return query select true, v_count, null::bigint;
end;
$$;

revoke all on function public.verify_audit_chain() from public, anon, authenticated;
grant execute on function public.verify_audit_chain() to authenticated;
