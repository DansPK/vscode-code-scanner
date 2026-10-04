import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();
export async function find(name: string) {
  return prisma.$queryRawUnsafe(`SELECT * FROM users WHERE name = '${name}'`);
}
