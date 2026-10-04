import { Pool } from "pg";
const pool = new Pool();
export async function find(name: string) {
  return pool.query("SELECT * FROM users WHERE name = $1", [name]);
}
