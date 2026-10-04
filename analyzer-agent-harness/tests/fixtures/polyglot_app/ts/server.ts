import express from "express";
import { exec } from "child_process";

const app = express();

app.get("/ping", (req, res) => {
  exec("ping -c 1 " + req.query.host, (err, out) => res.send(out));
});

app.get("/calc", (req, res) => {
  res.send(String(eval(req.query.expr as string)));
});
