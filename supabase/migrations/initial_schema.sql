-- Advanced Exam Tracker: Supabase schema
-- Run this entire file in Supabase Dashboard -> SQL Editor.

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null,
  created_at timestamptz not null default now()
);

create unique index if not exists profiles_username_lower_idx
on public.profiles (lower(username));

create table if not exists public.topic_progress (
  user_id uuid not null references auth.users(id) on delete cascade,
  topic_id integer not null,
  status text not null default 'NotStarted'
    check (status in ('NotStarted','InProgress','NeedsReview','Mastered')),
  last_reviewed timestamptz null,
  updated_at timestamptz not null default now(),
  primary key (user_id, topic_id)
);

create table if not exists public.exam_settings (
  user_id uuid primary key references auth.users(id) on delete cascade,
  exam_date timestamptz null,
  updated_at timestamptz not null default now()
);

alter table public.profiles enable row level security;
alter table public.topic_progress enable row level security;
alter table public.exam_settings enable row level security;

drop policy if exists "profiles_select_own" on public.profiles;
create policy "profiles_select_own"
on public.profiles for select
to authenticated
using (auth.uid() = id);

drop policy if exists "profiles_insert_own" on public.profiles;
create policy "profiles_insert_own"
on public.profiles for insert
to authenticated
with check (auth.uid() = id);

drop policy if exists "profiles_update_own" on public.profiles;
create policy "profiles_update_own"
on public.profiles for update
to authenticated
using (auth.uid() = id)
with check (auth.uid() = id);

drop policy if exists "topic_progress_select_own" on public.topic_progress;
create policy "topic_progress_select_own"
on public.topic_progress for select
to authenticated
using (auth.uid() = user_id);

drop policy if exists "topic_progress_insert_own" on public.topic_progress;
create policy "topic_progress_insert_own"
on public.topic_progress for insert
to authenticated
with check (auth.uid() = user_id);

drop policy if exists "topic_progress_update_own" on public.topic_progress;
create policy "topic_progress_update_own"
on public.topic_progress for update
to authenticated
using (auth.uid() = user_id)
with check (auth.uid() = user_id);

drop policy if exists "topic_progress_delete_own" on public.topic_progress;
create policy "topic_progress_delete_own"
on public.topic_progress for delete
to authenticated
using (auth.uid() = user_id);

drop policy if exists "exam_settings_select_own" on public.exam_settings;
create policy "exam_settings_select_own"
on public.exam_settings for select
to authenticated
using (auth.uid() = user_id);

drop policy if exists "exam_settings_insert_own" on public.exam_settings;
create policy "exam_settings_insert_own"
on public.exam_settings for insert
to authenticated
with check (auth.uid() = user_id);

drop policy if exists "exam_settings_update_own" on public.exam_settings;
create policy "exam_settings_update_own"
on public.exam_settings for update
to authenticated
using (auth.uid() = user_id)
with check (auth.uid() = user_id);

drop policy if exists "exam_settings_delete_own" on public.exam_settings;
create policy "exam_settings_delete_own"
on public.exam_settings for delete
to authenticated
using (auth.uid() = user_id);

-- Keep updated_at current.
create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists topic_progress_updated_at on public.topic_progress;
create trigger topic_progress_updated_at
before update on public.topic_progress
for each row execute function public.set_updated_at();

drop trigger if exists exam_settings_updated_at on public.exam_settings;
create trigger exam_settings_updated_at
before update on public.exam_settings
for each row execute function public.set_updated_at();

-- Automatically create a profile after a new Auth user is created.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
  insert into public.profiles (id, username)
  values (
    new.id,
    coalesce(
      nullif(new.raw_user_meta_data ->> 'username', ''),
      split_part(coalesce(new.email, 'user'), '@', 1)
    )
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute function public.handle_new_user();

-- Allow the browser client to use the Data API with RLS.
grant select, insert, update, delete on public.profiles to authenticated;
grant select, insert, update, delete on public.topic_progress to authenticated;
grant select, insert, update, delete on public.exam_settings to authenticated;
