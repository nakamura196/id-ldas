// Storage: one Durable Object with its own SQLite database (free plan; no D1 needed).
// The only data the ID server keeps. No passwords and no private keys.
import { DurableObject } from 'cloudflare:workers';

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,         -- random UUID
    name        TEXT NOT NULL,            -- name from ORCID
    created_at  INTEGER NOT NULL,
    orcid       TEXT,                     -- ORCID iD, e.g. 0000-0001-8245-7925
    status      TEXT NOT NULL DEFAULT 'pending',  -- pending | approved | rejected
    approved_by TEXT,                     -- ORCID iD of the admin who decided
    approved_at INTEGER,
    wallet      TEXT                      -- Ethereum address the person proved they control
  );
  
  CREATE TABLE IF NOT EXISTS credentials (
    id         TEXT PRIMARY KEY,          -- passkey credential ID (base64url)
    user_id    TEXT NOT NULL REFERENCES users(id),
    public_key TEXT NOT NULL,             -- COSE public key (base64url)
    counter    INTEGER NOT NULL DEFAULT 0,
    transports TEXT,                      -- JSON array
    created_at INTEGER NOT NULL
  );
  
  -- One-time challenges for passkey ceremonies (deleted when used).
  CREATE TABLE IF NOT EXISTS challenges (
    id         TEXT PRIMARY KEY,
    challenge  TEXT NOT NULL,
    user_id    TEXT,
    name       TEXT,
    expires_at INTEGER NOT NULL
  );
  
  CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id),
    expires_at INTEGER NOT NULL
  );
`;

// Columns added after the first deploy (2026-10-02). Old databases get them here.
const MIGRATIONS = [
  "ALTER TABLE users ADD COLUMN orcid TEXT",
  "ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'",
  "ALTER TABLE users ADD COLUMN approved_by TEXT",
  "ALTER TABLE users ADD COLUMN approved_at INTEGER",
  "ALTER TABLE users ADD COLUMN wallet TEXT",
];

export class Store extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    ctx.storage.sql.exec(SCHEMA);
    const have = new Set(ctx.storage.sql.exec('PRAGMA table_info(users)').toArray().map((c) => c.name));
    for (const m of MIGRATIONS) if (!have.has(m.split(' ')[5])) ctx.storage.sql.exec(m);
    ctx.storage.sql.exec('CREATE UNIQUE INDEX IF NOT EXISTS users_orcid ON users(orcid)');
    ctx.storage.sql.exec('CREATE UNIQUE INDEX IF NOT EXISTS users_wallet ON users(wallet)');
  }
  first(sql, params) {
    return this.ctx.storage.sql.exec(sql, ...params).toArray()[0] ?? null;
  }
  all(sql, params) {
    return this.ctx.storage.sql.exec(sql, ...params).toArray();
  }
  run(sql, params) {
    this.ctx.storage.sql.exec(sql, ...params);
  }
  // All statements succeed or none do.
  batch(statements) {
    this.ctx.storage.transactionSync(() => {
      for (const [sql, params] of statements) this.ctx.storage.sql.exec(sql, ...params);
    });
  }
}

// D1-style helper so the request code reads like ordinary SQL: db(env).prepare(sql).bind(...).first()
export function db(env) {
  const stub = env.STORE.get(env.STORE.idFromName('main'));
  const stmt = (sql, params = []) => ({
    sql, params,
    bind: (...p) => stmt(sql, p),
    first: () => stub.first(sql, params),
    all: () => stub.all(sql, params),
    run: () => stub.run(sql, params),
  });
  return {
    prepare: (sql) => stmt(sql),
    batch: (list) => stub.batch(list.map((s) => [s.sql, s.params])),
  };
}
