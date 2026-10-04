import { Pool } from "pg";
const pool = new Pool();
export async function findUser(name: string) {
  return pool.query("SELECT * FROM users WHERE name = '" + name + "'");
}
