const { Pool } = require("pg");

const pool = new Pool({
  user: "postgres",
  database: "verge",
  password: "limbo",
  host: "localhost",
  port: 5432,
});

pool.on("connect", () => {
  console.log("connected to db successfully");
});

pool.on("error", (err) => {
  console.log("connected to db successfully", err);
});

module.exports = pool;
