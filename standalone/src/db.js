import { randomBytes } from "node:crypto";
import fs from "node:fs";
import { join } from "node:path";
import { SQL } from "bun";

fs.mkdirSync(process.env.DATA_PATH || "./.data", {
  recursive: true,
});

let db;

async function initDb() {
  const dbUrl =
    process.env.DB_URL ||
    `sqlite://${join(process.env.DATA_PATH || "./.data", "db.sqlite")}`;

  db = new SQL(dbUrl);

  const isSqlite = db.options.adapter === "sqlite";
  const isPostgres = db.options.adapter === "postgres";
  if (isSqlite) {
    await db`PRAGMA journal_mode = WAL;`.simple();
    await db`PRAGMA synchronous = NORMAL;`.simple();
  }

  const changeIntToBigInt = async (tbl, col) => {
    if (isSqlite) return; // Irrelevant in SQLite.
    if (isPostgres) {
      await db`alter table ${db(tbl)} alter column ${db(col)} type bigint`.simple();
    } else {
      // Mysql needs modify column syntax...
      await db`alter table ${db(tbl)} modify column ${db(col)} bigint`.simple();
    }
  };

  await db`create table if not exists sessions (
    token text primary key not null,
    expires bigint not null,
    created bigint not null
  )`.simple();
  await changeIntToBigInt("sessions", "expires");
  await changeIntToBigInt("sessions", "created");

  await db`create table if not exists keys (
    siteKey text primary key not null,
    name text not null,
    secretHash text not null,
    jwtSecret text not null default '',
    config text not null,
    created bigint not null
  )`.simple();
  await changeIntToBigInt("keys", "created");

  try {
    await db`SELECT jwtSecret FROM keys LIMIT 1`;
  } catch {
    await db`ALTER TABLE keys ADD COLUMN jwtSecret text not null default ''`.simple();
  }

  const keysWithoutSecret =
    await db`SELECT siteKey FROM keys WHERE jwtSecret = ''`;
  for (const row of keysWithoutSecret) {
    const secret = randomBytes(32).toString("base64url");
    await db`UPDATE keys SET jwtSecret = ${secret} WHERE siteKey = ${row.siteKey || row.sitekey}`;
  }

  await db`create table if not exists solutions (
    siteKey text not null,
    bucket integer not null,
    count integer default 0,
    primary key (siteKey, bucket)
  )`.simple();

  await db`create table if not exists challenge_blocklist (
    sig text primary key not null,
    expires bigint not null
  )`.simple();
  await changeIntToBigInt("challenge_blocklist", "expires");

  await db`create table if not exists tokens (
    siteKey text not null,
    token text not null,
    expires bigint not null,
    primary key (siteKey, token)
  )`.simple();
  await changeIntToBigInt("tokens", "expires");

  await db`create table if not exists api_keys (
    id text not null,
    name text not null,
    tokenHash text not null,
    created bigint not null,
    primary key (id, tokenHash)
  )`.simple();
  await changeIntToBigInt("api_keys", "created");

  setInterval(async () => {
    try {
      const now = Date.now();

      await db`delete from sessions where expires < ${now}`;
      await db`delete from tokens where expires < ${now}`;
      await db`delete from challenge_blocklist where expires < ${now}`;
    } catch (e) {
      console.error("failed to cleanup:", e);
    }
  }, 60 * 1000);

  const now = Date.now();

  await db`delete from sessions where expires < ${now}`;
  await db`delete from tokens where expires < ${now}`;
  await db`delete from challenge_blocklist where expires < ${now}`;

  return db;
}

db = await initDb();

export { db };
