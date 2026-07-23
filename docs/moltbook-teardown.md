# How Moltbook exposed 1.5 million API keys in three days — and how to check your own Supabase app

Moltbook launched on January 28, 2026. It was an AI social network — a place where autonomous agents posted, replied, and messaged each other. Its founder said, on the record, that he "didn't write a single line of code." The whole thing was built with AI.

Roughly three days later, researchers at Wiz found that the entire production database was readable by anyone. Sitting in the open: about 1.5 million API authentication tokens, 35,000 email addresses, and the private messages between agents.

Nobody broke in. There was nothing to break. The front door had no lock, and the key to it was printed on the door.

If you've shipped anything on Supabase that an AI wrote for you, this teardown is worth ten minutes, because the failure wasn't exotic. It was the single most common way vibe-coded apps leak, and it's almost invisible until someone points a script at you.

## What actually went wrong

Moltbook's stack put its Supabase API key in client-side JavaScript, and left Row Level Security turned off on its tables. Those two facts are harmless on their own. Together they are a full public database.

Here's the mechanism, because the details are the whole point.

Supabase hands you two keys. The **anon key** (also called the publishable key) is *designed* to be public. It goes in your frontend. It identifies your project to Supabase's auto-generated REST API — think of it as a return address, not a password. Every Supabase quickstart puts it in client code, correctly, and that's fine.

What makes the anon key safe is **Row Level Security** — RLS. It's a Postgres feature. When you enable RLS on a table, every query gets filtered through policies you write: *this role can read these rows, that role can write those rows.* The anon key maps to the `anon` database role. With RLS on and sensible policies, an anonymous visitor holding your anon key can only touch what your policies allow — usually nothing sensitive.

With RLS **off**, none of that filtering happens. Supabase's REST layer will cheerfully let the `anon` role read, insert, update, and delete every row in the table. So the anon key — the one that's supposed to be public — becomes a skeleton key. Anyone who views source on your site has it. From there it's one `curl` command to dump your database.

That's the Moltbook chain, start to finish:

> anon key in the client bundle (expected, safe by itself) **+** RLS disabled on the tables (the missing lock) **=** every row public to anyone who opens dev tools.

There's a second key, the **service_role key**, that bypasses RLS entirely. That one must never touch client code — if it leaks, no policy can save you. Moltbook's problem wasn't the service_role key, though. It was the *safe* key made dangerous by a missing setting. That's what makes this failure so easy to ship: nothing looks wrong.

## Why the AI did this — and why it'll do it to you too

It's tempting to blame the model. Don't bother; the reason is structural, and understanding it is how you stop repeating it.

An AI writes code that satisfies the request. "Build me a social app where agents can post" produces a working schema, a working API, a working frontend. It runs. You test it while logged in as yourself, data flows, everything looks done.

RLS never gets enabled, because enabling it isn't part of *making the feature work* — it's part of *reasoning about who else can reach the database.* That reasoning requires holding a threat model in your head: anonymous clients will hit this endpoint, the anon key will be public, therefore I need policies. None of that appears in a natural-language prompt for a social app. The model optimizes for the functional requirement and silently skips the unstated security one.

So the app works perfectly in every test you run, and is wide open the moment it's live. The gap between "it works" and "it's safe" is exactly where these breaches live, and it's invisible from inside the happy path. When one audit firm scanned over 200 vibe-coded apps in early 2026, more than nine in ten had at least one flaw of this kind. Roughly 70% of apps built on one popular platform had RLS disabled entirely. Moltbook wasn't unlucky. It was typical.

## How to check your own app in five minutes

You can find this exact problem yourself, right now, on any app you own. Four steps.

**1. Confirm only your anon key is in the client.** Search your frontend code and your built bundle for your Supabase keys. The anon key being there is fine. The `service_role` key being there is a five-alarm fire — it bypasses RLS, so it must only ever live in server-side environment variables. If you're not sure which is which, decode the key at jwt.io and read the `role` claim: `anon` is the public one, `service_role` is the dangerous one.

**2. Check which tables have RLS on.** In the Supabase dashboard, the Table Editor shows an "Unrestricted" / RLS-disabled warning badge on exposed tables. Or run this in the SQL editor:

```sql
select tablename, rowsecurity
from pg_tables
where schemaname = 'public';
```

Every table where `rowsecurity` is `false` is reachable by anyone holding your anon key.

**3. Test it the way an attacker would — on your own project.** Take your anon key and your project URL and hit a table directly:

```bash
curl "https://YOUR-PROJECT.supabase.co/rest/v1/YOUR_TABLE?select=*" \
  -H "apikey: YOUR_ANON_KEY"
```

If that returns rows it shouldn't — user emails, messages, anything private — you've just reproduced the Moltbook breach against yourself. Better you than a stranger.

**4. If RLS is off, turn it on — but don't stop there.** Enabling RLS with no policies denies *all* access, which will break your app until you add policies that let the right users see the right rows. RLS is the lock; policies are who gets keys. You need both.

## The honest caveat

This manual check works, but it's a snapshot of one app and the tables you remembered to look at. Vibe-coded apps change every few days — a new AI-generated migration adds a table with RLS off, a refactor moves a key into the bundle, and last week's clean audit is stale. The failure classes are known and finite; the hard part is catching them every time the code moves, not once.

That's the gap I'm building **vibescan** to close: point it at your repo and your Supabase project, and it checks the whole schema and your git history for this chain — exposed keys, disabled RLS, permissive policies — and flags the anon-key-plus-open-table combination as one finding, with the reproduction, instead of two warnings you have to connect yourself. The secret and dependency scans are free and run locally; nothing leaves your machine. [→ link]

But even if you never touch it: run the four steps above on whatever you shipped last. The Moltbook founder found out from a security researcher, three days and 1.5 million keys too late. You can find out in five minutes, tonight, for free.

---

*Sources: Wiz's disclosure of the Moltbook exposure, and 2026 vibe-coding security research from Escape, Georgia Tech's Vibe Security Radar, and others. Figures are from secondary coverage — verify against primary reports before citing.*
