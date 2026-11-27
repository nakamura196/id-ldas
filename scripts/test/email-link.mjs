#!/usr/bin/env node
// End-to-end check of the sign-in link in the email, against a local `wrangler dev` (default http://localhost:8787).
//
//   npx wrangler dev --port 8787 &   # without RESEND_API_KEY the code and link come back in the response
//   node scripts/test/email-link.mjs [origin]
//
// Checks: the link signs in the browser that asked for it and returns to `next`; another browser
// gets 409 and no attempt is used; a wrong code is refused; the link works once; the typed code
// still works; the affiliation link works only with the session that asked for it.
const O = process.argv[2] || 'http://localhost:8787';
let failed = 0;
const ok = (cond, label) => { console.log(`${cond ? 'ok  ' : 'FAIL'} ${label}`); if (!cond) failed++; };

// A tiny cookie jar per "browser".
function browser() {
  const jar = {};
  return async function call(path, body) {
    const r = await fetch(O + path, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Origin: O,
        Cookie: Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; '),
      },
      body: JSON.stringify(body || {}),
    });
    for (const c of r.headers.getSetCookie?.() || []) {
      const [kv] = c.split(';');
      const [k, ...v] = kv.split('=');
      if (/Max-Age=0/.test(c)) delete jar[k]; else jar[k] = v.join('=');
    }
    const j = await r.json().catch(() => ({}));
    return { status: r.status, data: j.data?.attributes, error: j.errors?.[0]?.title, jar };
  };
}

function parseLink(link) {
  const u = new URL(link);
  const p = new URLSearchParams(u.hash.slice(1));
  return { path: u.pathname, c: p.get('c'), a: p.get('a'), k: p.get('k'), search: u.search };
}

const email = (tag) => `link-test-${tag}-${Date.now()}@example.ac.jp`;

// 1. Same browser: the link signs in and returns to next.
{
  const a = browser();
  const start = await a('/api/auth/email/start', { email: email('same'), next: '/authorize?x=1', name: 'Link Test' });
  ok(start.status === 200 && start.data?.devLink, 'start returns a dev link');
  const l = parseLink(start.data.devLink);
  ok(l.path === '/email-link' && l.search === '' && l.c === start.data.challengeId && l.k === start.data.devCode, 'id and code are in the #fragment, not the query');
  ok(Boolean(start.jar['__Host-eml']), 'browser cookie is set');

  const other = browser();
  const r409 = await other('/api/auth/email/link', { challengeId: l.c, code: l.k });
  ok(r409.status === 409, 'another browser gets 409');

  const wrong = await a('/api/auth/email/link', { challengeId: l.c, code: l.k === '000000' ? '111111' : '000000' });
  ok(wrong.status === 400, 'wrong code refused');

  const good = await a('/api/auth/email/link', { challengeId: l.c, code: l.k });
  ok(good.status === 200 && good.data?.next === '/authorize?x=1', 'same browser signs in and gets next');
  ok(Boolean(good.jar['__Host-sid']) && !good.jar['__Host-eml'], 'session set, browser cookie cleared');

  const again = await a('/api/auth/email/link', { challengeId: l.c, code: l.k });
  ok(again.status === 400, 'link works only once');

  const me = await fetch(`${O}/api/me`, { headers: { Cookie: `__Host-sid=${good.jar['__Host-sid']}` } }).then((r) => r.json());
  ok(me.data?.attributes?.name === 'Link Test' || me.data?.name === 'Link Test' || JSON.stringify(me).includes('Link Test'), 'display name typed before sending is kept');
}

// 2. The 409 from another browser does not use up attempts (5 tries from elsewhere, then the owner still signs in).
{
  const a = browser();
  const start = await a('/api/auth/email/start', { email: email('attempts') });
  const l = parseLink(start.data.devLink);
  const other = browser();
  for (let i = 0; i < 6; i++) await other('/api/auth/email/link', { challengeId: l.c, code: l.k });
  const good = await a('/api/auth/email/link', { challengeId: l.c, code: l.k });
  ok(good.status === 200, 'owner still signs in after other-browser tries');
}

// 3. Typing the code still works (also from another browser: that is how cross-device sign-in works).
{
  const a = browser();
  const start = await a('/api/auth/email/start', { email: email('typed') });
  const b = browser();
  const v = await b('/api/auth/email/verify', { challengeId: start.data.challengeId, code: start.data.devCode });
  ok(v.status === 200 && Boolean(v.jar['__Host-sid']), 'typed code signs in');
}

// 4. Affiliation link: works with the session that asked, not with another account.
{
  const a = browser();
  const s = await a('/api/auth/email/start', { email: email('affil-a') });
  await a('/api/auth/email/verify', { challengeId: s.data.challengeId, code: s.data.devCode });
  const ch = await a('/api/email/challenge', { email: 'someone@u-tokyo.ac.jp' });
  ok(ch.status === 200, 'affiliation challenge sent');

  const b = browser();
  const sb = await b('/api/auth/email/start', { email: email('affil-b') });
  await b('/api/auth/email/verify', { challengeId: sb.data.challengeId, code: sb.data.devCode });
  const stranger = await b('/api/email/verify', { challengeId: ch.data.challengeId, code: ch.data.devCode });
  ok(stranger.status !== 200, 'another account cannot use the affiliation link');

  const nobody = await browser()('/api/email/verify', { challengeId: ch.data.challengeId, code: ch.data.devCode });
  ok(nobody.status === 401, 'not signed in gets 401 (page shows the code)');

  const mine = await a('/api/email/verify', { challengeId: ch.data.challengeId, code: ch.data.devCode });
  ok(mine.status === 200 && mine.data?.emailDomain === 'u-tokyo.ac.jp', 'owner completes affiliation');
}

// 5. The link page itself is a static page that does nothing on load.
{
  const r = await fetch(`${O}/email-link`);
  const html = await r.text();
  ok(r.status === 200 && html.includes('/api/auth/email/link') && html.includes('onclick'), 'link page served; sign-in only on button press');
}

console.log(failed ? `\n${failed} failed` : '\nall passed');
process.exit(failed ? 1 : 0);
