-- =====================================================================
-- People's Choice Player of the Week — Database Schema (simplified)
-- =====================================================================
-- Run this in your Supabase project's SQL Editor. Postgres 15+.
--
-- Simpler than a version with separate edge functions: every rule is
-- enforced by a plain Postgres function or an RLS policy, called
-- directly from the HTML pages via supabase-js. No CLI, no Deno, no
-- separate deploy step — just this one file, then two HTML files with
-- your project URL/key pasted in.
--
-- IMPORTANT: this was written carefully but could not be executed
-- against a live Postgres instance in the environment that produced it
-- (no network / no local Postgres available there). Run it in a
-- scratch/staging Supabase project first and confirm it applies
-- cleanly before using it on anything real.
-- =====================================================================

create extension if not exists pgcrypto;   -- gen_random_uuid(), digest()
create extension if not exists pg_cron;    -- scheduled jobs (bottom of file)

-- ---------------------------------------------------------------------
-- ADMINS
-- Add yourself after creating your Supabase Auth account:
--   insert into admins (user_id) values ('<your-auth-user-uuid>');
-- ---------------------------------------------------------------------
create table admins (
    user_id     uuid primary key references auth.users(id) on delete cascade,
    created_at  timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- SEASONS / PLAYERS
-- ---------------------------------------------------------------------
create table seasons (
    id          uuid primary key default gen_random_uuid(),
    label       text not null,
    starts_on   date not null,
    ends_on     date,
    is_active   boolean not null default true,
    created_at  timestamptz not null default now()
);

create table players (
    id              uuid primary key default gen_random_uuid(),
    season_id       uuid not null references seasons(id) on delete cascade,
    name            text not null,
    jersey_number   int,
    photo_url       text,
    created_at      timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- POLLS
-- "weekly" = a normal week. "tiebreaker" = auto-created when a weekly
-- poll ends tied, linked back via parent_poll_id. Chains support ties
-- within tiebreakers too.
--
-- status: scheduled -> awaiting_tiebreaker (if tied) OR decided -> published
-- "Currently open for voting" is never stored — always computed live
-- as (now() between opens_at and closes_at), so it can't drift out of
-- sync with real time.
-- ---------------------------------------------------------------------
create type poll_type as enum ('weekly', 'tiebreaker', 'test');
create type poll_status as enum ('scheduled', 'awaiting_tiebreaker', 'decided', 'published');

create table polls (
    id                  uuid primary key default gen_random_uuid(),
    season_id           uuid not null references seasons(id) on delete cascade,
    parent_poll_id      uuid references polls(id) on delete cascade,
    poll_type           poll_type not null default 'weekly',
    week_number         int,
    opens_at            timestamptz not null,
    closes_at           timestamptz not null,
    publish_at          timestamptz not null,
    status              poll_status not null default 'scheduled',
    winner_player_id    uuid references players(id),
    created_at          timestamptz not null default now(),
    check (closes_at > opens_at),
    check (publish_at >= closes_at)
);

create index idx_polls_status_closes on polls (status, closes_at);
create index idx_polls_status_publish on polls (status, publish_at);
create index idx_polls_parent on polls (parent_poll_id);

create table poll_eligible_players (
    poll_id     uuid not null references polls(id) on delete cascade,
    player_id   uuid not null references players(id) on delete cascade,
    primary key (poll_id, player_id)
);

-- ---------------------------------------------------------------------
-- VOTES
-- voter_hash = sha256(poll_id || ':' || verified_email), computed
-- inside cast_vote() below — raw email is never stored. Hashing the
-- email PER POLL means the same person's votes can't be linked across
-- different weeks by anyone with database access.
--
-- The UNIQUE constraint is what actually enforces one-vote-per-poll,
-- atomically, even under concurrent duplicate requests. There is no
-- INSERT policy on this table for anyone — the only way a row is ever
-- created is through cast_vote(), which runs as SECURITY DEFINER.
--
-- player_id deliberately does NOT cascade on delete: a player with
-- recorded votes should block deletion (via delete_player() below)
-- rather than silently erasing vote history / corrupting a tally.
-- ---------------------------------------------------------------------
create table votes (
    id          uuid primary key default gen_random_uuid(),
    poll_id     uuid not null references polls(id) on delete cascade,
    player_id   uuid not null references players(id),
    voter_hash  text not null,
    created_at  timestamptz not null default now(),
    unique (poll_id, voter_hash)
);

create index idx_votes_poll on votes (poll_id);

-- =====================================================================
-- PUBLIC-SAFE VIEW — the public page reads this, never `polls` directly.
-- Only exposes winner_player_id once status = 'published'.
-- =====================================================================
create view public_poll_results
with (security_invoker = off) as
select
    p.id as poll_id, p.season_id, p.poll_type, p.week_number, p.parent_poll_id,
    p.opens_at, p.closes_at, p.publish_at, p.status,
    case when p.status = 'published' then p.winner_player_id else null end as winner_player_id
from polls p;

-- =====================================================================
-- ROW LEVEL SECURITY
-- =====================================================================
alter table seasons enable row level security;
alter table players enable row level security;
alter table poll_eligible_players enable row level security;
alter table polls enable row level security;
alter table votes enable row level security;
alter table admins enable row level security;

-- Everyone can read seasons/players/eligible-lists (names, photos —
-- nothing sensitive).
create policy "public read seasons" on seasons for select using (true);
create policy "public read players" on players for select using (true);
create policy "public read eligible players" on poll_eligible_players for select using (true);

-- =====================================================================
-- is_admin() — used inside RLS policies and other functions.
-- Kept internal: not directly callable by anon/authenticated, since
-- letting anyone probe arbitrary user ids is a minor needless leak.
-- Policies and SECURITY DEFINER functions can still call it internally
-- regardless of this restriction. Defined BEFORE the policies below
-- so they can reference it.
-- =====================================================================
create or replace function is_admin(p_user_id uuid) returns boolean
language sql stable security definer as $$
    select exists(select 1 from admins where user_id = p_user_id);
$$;
revoke execute on function is_admin(uuid) from public;

-- Admins can create/update seasons & players directly from the admin
-- dashboard (no separate API layer needed — RLS is the enforcement).
create policy "admin write seasons" on seasons for insert with check (is_admin(auth.uid()));
create policy "admin update seasons" on seasons for update using (is_admin(auth.uid()));
create policy "admin write players" on players for insert with check (is_admin(auth.uid()));
create policy "admin update players" on players for update using (is_admin(auth.uid()));

-- Admins can read full poll rows directly (status, internals). The
-- PUBLIC still can't — they use public_poll_results instead.
create policy "admin read polls" on polls for select using (is_admin(auth.uid()));

-- `votes` gets NO policy for anyone, admin included — even you should
-- only ever see vote counts through admin_poll_vote_counts() below,
-- never raw rows. `admins` gets no public policy either.

grant select on seasons, players, poll_eligible_players, public_poll_results
    to anon, authenticated;

-- Convenience for the admin dashboard's login check: "is the CURRENT
-- user an admin?" — safe to expose since it only ever answers about
-- yourself.
create or replace function am_i_admin() returns boolean
language sql stable security definer as $$
    select is_admin(auth.uid());
$$;
revoke execute on function am_i_admin() from public;
grant execute on function am_i_admin() to authenticated;

-- =====================================================================
-- cast_vote() — the ONLY way a vote is ever written.
-- Enforces every rule from the spec:
--   - must be authenticated (OTP-verified email)          -> auth.uid() check
--   - voting before/after the window                      -> compared to server's own now()
--   - manipulated client timestamps                        -> no client timestamp is ever read
--   - tampering with the selected player / ineligible pick -> checked against poll_eligible_players
--   - duplicate submissions / replay                       -> UNIQUE(poll_id, voter_hash)
-- Only `authenticated` can call this — anon is explicitly blocked, so
-- a visitor must complete email-OTP verification first.
-- =====================================================================
create or replace function cast_vote(p_poll_id uuid, p_player_id uuid)
returns void
language plpgsql
security definer
as $$
declare
    v_email     text;
    v_opens     timestamptz;
    v_closes    timestamptz;
    v_eligible  boolean;
    v_hash      text;
begin
    if auth.uid() is null then
        raise exception 'You need to verify your email before voting.';
    end if;

    select email into v_email from auth.users where id = auth.uid();
    if v_email is null then
        raise exception 'Could not verify your account email.';
    end if;
    v_email := lower(trim(v_email));

    select opens_at, closes_at into v_opens, v_closes
    from polls where id = p_poll_id;
    if not found then
        raise exception 'Poll not found.';
    end if;

    if now() < v_opens then
        raise exception 'Voting has not opened yet.';
    end if;
    if now() >= v_closes then
        raise exception 'Voting has closed for this poll.';
    end if;

    select exists(
        select 1 from poll_eligible_players
        where poll_id = p_poll_id and player_id = p_player_id
    ) into v_eligible;
    if not v_eligible then
        raise exception 'That player is not eligible in this poll.';
    end if;

    v_hash := encode(digest(p_poll_id::text || ':' || v_email, 'sha256'), 'hex');

    begin
        insert into votes (poll_id, player_id, voter_hash)
        values (p_poll_id, p_player_id, v_hash);
    exception when unique_violation then
        raise exception 'You have already voted in this poll.';
    end;
end;
$$;
revoke execute on function cast_vote(uuid, uuid) from public;
grant execute on function cast_vote(uuid, uuid) to authenticated;

-- =====================================================================
-- create_weekly_poll() — admin-only (checked internally), computes the
-- correct Central-Time schedule:
--   opens_at   = Friday 10:00 PM Central
--   closes_at  = following Wednesday 12:00 AM Central (Friday + 5 days)
--   publish_at = that same Wednesday 8:00 AM Central
-- Postgres's `timestamp AT TIME ZONE 'America/Chicago'` correctly
-- accounts for DST using the IANA tz database for that specific date.
-- =====================================================================
create or replace function create_weekly_poll(
    p_season_id uuid,
    p_week_number int,
    p_friday_date date,
    p_eligible_player_ids uuid[]
) returns uuid
language plpgsql
security definer
as $$
declare
    v_poll_id uuid;
    v_opens   timestamptz;
    v_closes  timestamptz;
    v_publish timestamptz;
    v_player  uuid;
begin
    if not is_admin(auth.uid()) then
        raise exception 'Not authorized.';
    end if;

    v_opens   := (p_friday_date::timestamp + time '22:00') at time zone 'America/Chicago';
    v_closes  := ((p_friday_date + 5)::timestamp + time '00:00') at time zone 'America/Chicago';
    v_publish := ((p_friday_date + 5)::timestamp + time '08:00') at time zone 'America/Chicago';

    insert into polls (season_id, poll_type, week_number, opens_at, closes_at, publish_at, status)
    values (p_season_id, 'weekly', p_week_number, v_opens, v_closes, v_publish, 'scheduled')
    returning id into v_poll_id;

    foreach v_player in array p_eligible_player_ids loop
        insert into poll_eligible_players (poll_id, player_id) values (v_poll_id, v_player);
    end loop;

    return v_poll_id;
end;
$$;
revoke execute on function create_weekly_poll(uuid, int, date, uuid[]) from public;
grant execute on function create_weekly_poll(uuid, int, date, uuid[]) to authenticated;

-- =====================================================================
-- delete_poll() — admin-only. Deleting a poll cascades to its
-- eligible-player list, its votes, and (thanks to parent_poll_id ON
-- DELETE CASCADE on the polls table) any tiebreaker rounds spawned
-- from it. This permanently removes it from the public archive if it
-- was ever published — there's no undo, so the admin UI confirms
-- before calling this.
-- =====================================================================
create or replace function delete_poll(p_poll_id uuid) returns void
language plpgsql
security definer
as $$
begin
    if not is_admin(auth.uid()) then
        raise exception 'Not authorized.';
    end if;

    delete from polls where id = p_poll_id;
end;
$$;
revoke execute on function delete_poll(uuid) from public;
grant execute on function delete_poll(uuid) to authenticated;

-- =====================================================================
-- delete_player() — admin-only. A player who has any recorded votes,
-- or who has won a poll, cannot be deleted — that's enforced by the
-- (deliberately non-cascading) foreign keys on votes.player_id and
-- polls.winner_player_id, not just by this function. This catches
-- that and turns it into a clear message rather than a raw DB error.
-- =====================================================================
create or replace function delete_player(p_player_id uuid) returns void
language plpgsql
security definer
as $$
begin
    if not is_admin(auth.uid()) then
        raise exception 'Not authorized.';
    end if;

    begin
        delete from players where id = p_player_id;
    exception when foreign_key_violation then
        raise exception 'This player has votes recorded (or has won a poll) and can''t be removed. You can still leave them off future weeks by unchecking them when creating a poll.';
    end;
end;
$$;
revoke execute on function delete_player(uuid) from public;
grant execute on function delete_player(uuid) to authenticated;

-- =====================================================================
-- create_test_poll() — admin-only. Opens immediately and closes after
-- p_duration_minutes (default 5), so you can walk through the real
-- voting flow yourself — email OTP, selecting a player, hidden
-- results, the automated close/publish cycle, even a tie triggering a
-- real tiebreaker round — without waiting for a real Friday-to-
-- Wednesday window.
--
-- poll_type = 'test' rather than 'weekly' on purpose: it goes through
-- the exact same automation as a real poll, but is excluded from the
-- public archive, season standings, and season vote totals, so
-- testing never contaminates real season data.
-- =====================================================================
create or replace function create_test_poll(
    p_season_id uuid,
    p_eligible_player_ids uuid[],
    p_duration_minutes int default 5
) returns uuid
language plpgsql
security definer
as $$
declare
    v_poll_id uuid;
    v_closes  timestamptz;
    v_player  uuid;
begin
    if not is_admin(auth.uid()) then
        raise exception 'Not authorized.';
    end if;
    if array_length(p_eligible_player_ids, 1) is null or array_length(p_eligible_player_ids, 1) < 2 then
        raise exception 'Pick at least 2 players for the test poll.';
    end if;

    v_closes := now() + make_interval(mins => greatest(p_duration_minutes, 1));

    insert into polls (season_id, poll_type, week_number, opens_at, closes_at, publish_at, status)
    values (p_season_id, 'test', null, now(), v_closes, v_closes + interval '1 minute', 'scheduled')
    returning id into v_poll_id;

    foreach v_player in array p_eligible_player_ids loop
        insert into poll_eligible_players (poll_id, player_id) values (v_poll_id, v_player);
    end loop;

    return v_poll_id;
end;
$$;
revoke execute on function create_test_poll(uuid, uuid[], int) from public;
grant execute on function create_test_poll(uuid, uuid[], int) to authenticated;

-- =====================================================================
-- admin_poll_vote_counts() — admin-only (checked internally). The only
-- way raw vote counts are ever readable, by anyone, for any reason.
-- =====================================================================
create or replace function admin_poll_vote_counts(p_poll_id uuid)
returns table (player_id uuid, player_name text, vote_count bigint)
language plpgsql
security definer
as $$
begin
    if not is_admin(auth.uid()) then
        raise exception 'Not authorized.';
    end if;

    return query
        select pl.id, pl.name, count(v.id)
        from votes v
        join players pl on pl.id = v.player_id
        where v.poll_id = p_poll_id
        group by pl.id, pl.name
        order by count(v.id) desc;
end;
$$;
revoke execute on function admin_poll_vote_counts(uuid) from public;
grant execute on function admin_poll_vote_counts(uuid) to authenticated;

-- =====================================================================
-- season_award_standings() — admin-only (checked internally).
--   1st tiebreak: most weekly POTW wins
--   2nd tiebreak: highest accumulated raw votes across the season
--   3rd tiebreak: earliest player.created_at (deterministic, decided
--                 up front rather than picked arbitrarily later)
-- =====================================================================
create or replace function season_award_standings(p_season_id uuid)
returns table (player_id uuid, player_name text, potw_wins bigint, total_votes bigint)
language plpgsql
security definer
as $$
begin
    if not is_admin(auth.uid()) then
        raise exception 'Not authorized.';
    end if;

    return query
    with weekly_wins as (
        select winner_player_id as pid, count(*) as wins
        from polls
        where season_id = p_season_id and poll_type = 'weekly'
          and status = 'published' and winner_player_id is not null
        group by winner_player_id
    ),
    vote_totals as (
        select v.player_id as pid, count(*) as total
        from votes v join polls p on p.id = v.poll_id
        where p.season_id = p_season_id and p.poll_type = 'weekly'
        group by v.player_id
    )
    select pl.id, pl.name, coalesce(ww.wins,0), coalesce(vt.total,0)
    from players pl
    left join weekly_wins ww on ww.pid = pl.id
    left join vote_totals vt on vt.pid = pl.id
    where pl.season_id = p_season_id
    order by coalesce(ww.wins,0) desc, coalesce(vt.total,0) desc, pl.created_at asc;
end;
$$;
revoke execute on function season_award_standings(uuid) from public;
grant execute on function season_award_standings(uuid) to authenticated;

-- =====================================================================
-- public_season_champion() — the ONLY public-facing season-award
-- exposure. Deliberately narrow: just the #1 player's name, and only
-- once the season is marked concluded.
-- =====================================================================
create or replace function public_season_champion(p_season_id uuid)
returns table (player_id uuid, player_name text)
language sql
stable
security definer
as $$
    with weekly_wins as (
        select winner_player_id as pid, count(*) as wins
        from polls
        where season_id = p_season_id and poll_type = 'weekly'
          and status = 'published' and winner_player_id is not null
        group by winner_player_id
    ),
    vote_totals as (
        select v.player_id as pid, count(*) as total
        from votes v join polls p on p.id = v.poll_id
        where p.season_id = p_season_id and p.poll_type = 'weekly'
        group by v.player_id
    ),
    ranked as (
        select pl.id, pl.name, coalesce(ww.wins,0) as wins, coalesce(vt.total,0) as total
        from players pl
        left join weekly_wins ww on ww.pid = pl.id
        left join vote_totals vt on vt.pid = pl.id
        where pl.season_id = p_season_id
    )
    select id, name from ranked
    where exists (select 1 from seasons se where se.id = p_season_id and se.is_active = false)
    order by wins desc, total desc
    limit 1;
$$;
revoke execute on function public_season_champion(uuid) from public;
grant execute on function public_season_champion(uuid) to anon, authenticated;

-- =====================================================================
-- AUTOMATION: close polls whose window ended, detect ties, spawn
-- tiebreaker polls as needed. Runs on a schedule (see bottom).
-- =====================================================================
create or replace function process_poll_closures() returns void
language plpgsql security definer as $$
declare
    r               record;
    v_max_count     int;
    v_tied_players  uuid[];
    v_new_poll_id   uuid;
    v_pid           uuid;
begin
    for r in
        select id, season_id from polls
        where status = 'scheduled' and closes_at <= now()
    loop
        select max(cnt) into v_max_count
        from (select player_id, count(*) as cnt from votes where poll_id = r.id group by player_id) c;

        if v_max_count is null then
            update polls set status = 'decided', winner_player_id = null where id = r.id;
            continue;
        end if;

        select array_agg(player_id) into v_tied_players
        from (select player_id, count(*) as cnt from votes where poll_id = r.id group by player_id) c
        where cnt = v_max_count;

        if array_length(v_tied_players, 1) = 1 then
            update polls set status = 'decided', winner_player_id = v_tied_players[1] where id = r.id;
        else
            insert into polls (season_id, parent_poll_id, poll_type, week_number,
                                opens_at, closes_at, publish_at, status)
            values (r.season_id, r.id, 'tiebreaker', null,
                    now(), now() + interval '24 hours', now() + interval '25 hours', 'scheduled')
            returning id into v_new_poll_id;

            foreach v_pid in array v_tied_players loop
                insert into poll_eligible_players (poll_id, player_id) values (v_new_poll_id, v_pid);
            end loop;

            update polls set status = 'awaiting_tiebreaker' where id = r.id;
        end if;
    end loop;
end;
$$;
revoke execute on function process_poll_closures() from public;

-- =====================================================================
-- AUTOMATION: publish decided polls once publish_at arrives. A
-- tiebreaker's winner propagates up to the original weekly poll, so a
-- weekly poll always ends up with exactly one official winner no
-- matter how many tiebreaker rounds it took.
-- =====================================================================
create or replace function process_poll_publications() returns void
language plpgsql security definer as $$
declare
    r           record;
    v_root_id   uuid;
begin
    for r in
        select id, poll_type, parent_poll_id, winner_player_id
        from polls where status = 'decided' and publish_at <= now()
    loop
        update polls set status = 'published' where id = r.id;

        if r.poll_type = 'tiebreaker' then
            with recursive chain as (
                select id, poll_type, parent_poll_id from polls where id = r.parent_poll_id
                union all
                select p.id, p.poll_type, p.parent_poll_id
                from polls p join chain c on p.id = c.parent_poll_id
            )
            select id into v_root_id from chain where poll_type in ('weekly','test') limit 1;

            if v_root_id is not null then
                update polls set status = 'published', winner_player_id = r.winner_player_id
                where id = v_root_id;
            end if;
        end if;
    end loop;
end;
$$;
revoke execute on function process_poll_publications() from public;

-- =====================================================================
-- SCHEDULING — runs both automation functions every 2 minutes.
-- =====================================================================
select cron.schedule('process-poll-closures', '*/2 * * * *',
    $$ select process_poll_closures(); $$);

select cron.schedule('process-poll-publications', '*/2 * * * *',
    $$ select process_poll_publications(); $$);
