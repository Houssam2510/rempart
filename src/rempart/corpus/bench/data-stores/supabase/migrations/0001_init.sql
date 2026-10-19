-- rempart-expect: DATA-SUPABASE-RLS-MISSING
create table public.profiles (id uuid primary key, email text);

-- rempart-safe: DATA-SUPABASE-RLS-MISSING
create table public.orders (id uuid primary key, user_id uuid, total numeric);
alter table public.orders enable row level security;
create policy "own orders" on public.orders for select using (auth.uid() = user_id);
