-- =====================================================================
-- 0004  Private storage bucket
-- =====================================================================

-- public = false  -> no public URLs ever work for this bucket.
-- Size and MIME limits here are a backup; the Edge Function checks them first.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('documents', 'documents', false, 5242880,
        array['application/pdf', 'image/png', 'image/jpeg'])
on conflict (id) do update
  set public             = false,
      file_size_limit    = excluded.file_size_limit,
      allowed_mime_types = excluded.allowed_mime_types;

-- We create NO permissive policy on storage.objects. With RLS on, that means the
-- browser (anon / authenticated keys) cannot list, read, upload, overwrite or delete.
-- Only Edge Functions (service role) touch the bucket, after checking permissions.
--
-- Belt and braces: this RESTRICTIVE policy is AND-ed with every other policy, so even
-- if someone later adds a permissive "allow all" storage policy by mistake, the
-- 'documents' bucket stays closed to browser keys.
create policy documents_bucket_closed_to_clients on storage.objects
  as restrictive
  for all
  to anon, authenticated
  using (bucket_id <> 'documents')
  with check (bucket_id <> 'documents');
