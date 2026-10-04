const express = require("express");
const { exec } = require("child_process");
const app = express();

app.get("/run", function (req, res) {
  exec(req.query.cmd, function (err, stdout) {
    res.send(stdout);
  });
});

app.get("/redirect", function (req, res) {
  res.redirect(req.query.url);
});
