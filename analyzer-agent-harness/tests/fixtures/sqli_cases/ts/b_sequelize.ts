import { Sequelize, QueryTypes } from "sequelize";
const sequelize = new Sequelize("sqlite::memory:");
export async function find(name: string) {
  return sequelize.query("SELECT * FROM users WHERE name = '" + name + "'", { type: QueryTypes.SELECT });
}
