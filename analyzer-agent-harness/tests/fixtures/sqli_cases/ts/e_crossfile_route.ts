import express from "express";
import { findUser } from "./e_crossfile_repo";
const app = express();
app.get("/e", async (req, res) => res.json(await findUser(req.query.name as string)));
