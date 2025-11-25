// server.js
require('dotenv').config();

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const app = express();
const jwt = require("jsonwebtoken");

app.use(express.json());

// ----------------------
// DB Connect
// ----------------------
const db = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

// ----------------------
// Middleware ตรวจสอบ Token
// ----------------------
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.customer = decoded;  // เก็บข้อมูลลูกค้าไว้ใช้งาน
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

// ----------------------
// ping test
// ----------------------
app.get('/ping', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT NOW() AS now');
    res.json({ status: 'ok', time: rows[0].now });
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// ----------------------
// Register
// ----------------------
app.post("/auth/register", async (req, res) => {
  const { username, password, fullname, address, phone, email } = req.body;

  const hash = await bcrypt.hash(password, 10);

  await db.query(
    "INSERT INTO tbl_customers (username, password, fullname, address, phone, email) VALUES (?, ?, ?, ?, ?, ?)",
    [username, hash, fullname, address, phone, email]
  );

  res.json({ message: "Register success" });
});

// ----------------------
// Login
// ----------------------
app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body;

  const [rows] = await db.query(
    "SELECT * FROM tbl_customers WHERE username = ?",
    [username]
  );

  if (rows.length === 0)
    return res.status(400).json({ message: "Username not found" });

  const customer = rows[0];

  const match = await bcrypt.compare(password, customer.password);
  if (!match) return res.status(400).json({ message: "Password incorrect" });

  // SIGN TOKEN ด้วย customer_id (ถูกต้อง)
  const token = jwt.sign(
    { customer_id: customer.customer_id, fullname: customer.fullname },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );

  res.json({ token });
});

// ----------------------
// GET customers
// ----------------------
app.get("/customers", auth, async (req, res) => {
  const [rows] = await db.query(
    "SELECT customer_id, username, fullname, email FROM tbl_customers"
  );
  res.json(rows);
});

// ----------------------
// GET menus + restaurants
// ----------------------
app.get("/menus", async (req, res) => {
  const [rows] = await db.query(`
    SELECT m.menu_id, m.name AS menu_name, r.name AS restaurant_name, m.price
    FROM tbl_menus m
    JOIN tbl_restaurants r ON m.restaurant_id = r.restaurant_id
  `);

  res.json(rows);
});

// ----------------------
// POST orders
// ----------------------
app.post("/orders", auth, async (req, res) => {
  const { restaurant_id, menu_id, quantity } = req.body;

  const [menuData] = await db.query(
    "SELECT price FROM tbl_menus WHERE menu_id = ?",
    [menu_id]
  );

  if (!menuData.length) {
    return res.status(400).json({ message: "Menu not found" });
  }

  const price = menuData[0].price;
  const total = price * quantity;

  await db.query(
    "INSERT INTO tbl_orders (customer_id, restaurant_id, menu_id, quantity, price, total, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [req.customer.customer_id, restaurant_id, menu_id, quantity, price, total, "Pending"]
  );

  res.json({ message: "Order success", total });
});

// ----------------------
// GET order summary
// ----------------------
app.get("/orders/summary", auth, async (req, res) => {
  const customerId = req.customer.customer_id;

  const [[result]] = await db.query(`
    SELECT c.fullname AS customer_name, SUM(o.total) AS total_amount
    FROM tbl_orders o
    JOIN tbl_customers c ON o.customer_id = c.customer_id
    WHERE o.customer_id = ?
  `, [customerId]);

  res.json(result);
});

// ----------------------
app.listen(3000, () =>
  console.log("Server running on port 3000")
);
