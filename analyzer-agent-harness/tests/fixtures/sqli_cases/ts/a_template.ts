import express from "express";
import { Pool } from "pg";
const pool = new Pool();
const app = express();
app.get("/a", async (req, res) => {
  const r = await pool.query(`SELECT * FROM users WHERE name = '${req.query.name}'`);
  res.json(r.rows);
});
