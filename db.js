const { Pool } = require("pg");
const bcrypt = require("bcrypt");
require("dotenv").config();

// Create connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // Required for most hosted providers like Supabase/Neon
  keepAlive: true,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
  max: 20
});

async function initDb() {
  const client = await pool.connect();
  try {
    // Users Table
    await client.query(`CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT,
            username TEXT UNIQUE,
            hash TEXT,
            role TEXT,
            initials TEXT
        )`);

    // Items Table
    await client.query(`CREATE TABLE IF NOT EXISTS items (
            id TEXT PRIMARY KEY,
            name TEXT,
            sku TEXT,
            category TEXT,
            qty INTEGER,
            unit TEXT,
            threshold INTEGER,
            unit_cost REAL DEFAULT 0,
            notes TEXT
        )`);

    // Check if unit_cost exists (migration for items)
    const itemsInfo = await client.query(
      `SELECT column_name FROM information_schema.columns WHERE table_name = 'items'`,
    );
    const hasCost = itemsInfo.rows.some((c) => c.column_name === "unit_cost");
    if (!hasCost) {
      await client.query(
        `ALTER TABLE items ADD COLUMN unit_cost REAL DEFAULT 0`,
      );
      console.log("Migration: unit_cost column added.");
    }

    // Check if image_url exists (migration for items - Task #2)
    const hasImage = itemsInfo.rows.some((c) => c.column_name === "image_url");
    if (!hasImage) {
      await client.query(`ALTER TABLE items ADD COLUMN image_url TEXT`);
      console.log("Migration: image_url column added.");
    }

    // Audit Log Table
    await client.query(`CREATE TABLE IF NOT EXISTS audit (
            id SERIAL PRIMARY KEY,
            ts TEXT,
            event TEXT,
            detail TEXT,
            "user" TEXT
        )`);

    // Trim Table
    await client.query(`CREATE TABLE IF NOT EXISTS trim (
            id TEXT PRIMARY KEY,
            item_id TEXT,
            unit_of_measurement TEXT,
            unit_quantity REAL,
            amount REAL,
            unit_cost REAL
        )`);

    // Fabric Table
    await client.query(`CREATE TABLE IF NOT EXISTS fabric (
            id TEXT PRIMARY KEY,
            fabric_name TEXT,
            consumption REAL,
            unit_cost REAL
        )`);

    // Drop legacy production table to allow strict batch workflow
    await client.query(`DROP TABLE IF EXISTS production`);

    // Products Batch Table
    await client.query(`CREATE TABLE IF NOT EXISTS product_batches (
            id TEXT PRIMARY KEY,
            product_id TEXT,
            batch_number INTEGER,
            produced_qty INTEGER,
            total_duration TEXT,
            created_at TEXT
        )`);

    // Batch Materials (Trims and Fabrics used)
    await client.query(`CREATE TABLE IF NOT EXISTS batch_materials (
            id TEXT PRIMARY KEY,
            batch_id TEXT,
            material_id TEXT,
            material_type TEXT,
            consumed_qty REAL,
            unit_cost REAL,
            total_cost REAL
        )`);

    // Batch Stages
    await client.query(`CREATE TABLE IF NOT EXISTS batch_stages (
            id TEXT PRIMARY KEY,
            batch_id TEXT,
            stage_name TEXT,
            start_date TEXT,
            end_date TEXT,
            duration TEXT
        )`);

    // Migration: Fix Batch Numbering (Re-assign sequentially by creation order)
    const batches = await client.query(
      "SELECT id FROM product_batches ORDER BY created_at ASC",
    );
    if (batches.rows.length > 0) {
      for (let i = 0; i < batches.rows.length; i++) {
        await client.query(
          "UPDATE product_batches SET batch_number = $1 WHERE id = $2",
          [i + 1, batches.rows[i].id],
        );
      }
    }

    // Setup initial default Admin if no users exist
    const userCountRes = await client.query(
      "SELECT COUNT(*) as count FROM users",
    );
    const userCount = parseInt(userCountRes.rows[0].count, 10);
    if (userCount === 0) {
      const adminHash = await bcrypt.hash("Admin@123", 10);
      const staffHash = await bcrypt.hash("Staff@123", 10);

      await client.query(
        "INSERT INTO users (id, name, username, hash, role, initials) VALUES ($1, $2, $3, $4, $5, $6)",
        ["u1", "Admin User", "admin", adminHash, "admin", "AU"],
      );
      await client.query(
        "INSERT INTO users (id, name, username, hash, role, initials) VALUES ($1, $2, $3, $4, $5, $6)",
        ["u2", "Staff Member", "staff", staffHash, "staff", "SM"],
      );
    }

    // Setup default items if they don't exist
    const itemCountRes = await client.query(
      "SELECT COUNT(*) as count FROM items",
    );
    const itemCount = parseInt(itemCountRes.rows[0].count, 10);
    if (itemCount === 0) {
      const itemsList = [
        {
          id: "i1",
          name: "Classic Tote Bag",
          sku: "NB-TOT-001",
          category: "Products",
          qty: 42,
          unit: "pcs",
          threshold: 10,
          cost: 450,
          notes: "Bestseller. Tan leather.",
        },
        {
          id: "i2",
          name: "Laptop Backpack",
          sku: "NB-LAP-002",
          category: "Products",
          qty: 18,
          unit: "pcs",
          threshold: 5,
          cost: 1200,
          notes: '15" padded compartment.',
        },
        {
          id: "i3",
          name: "Mini Crossbody",
          sku: "NB-CRS-003",
          category: "Products",
          qty: 7,
          unit: "pcs",
          threshold: 8,
          cost: 350,
          notes: "Low stock - reorder soon.",
        },
        {
          id: "i4",
          name: "Full-Grain Cowhide Leather",
          sku: "RM-LTH-001",
          category: "Raw Materials",
          qty: 120,
          unit: "meters",
          threshold: 30,
          cost: 250,
          notes: "Primary material. Ethiopian sourced.",
        },
        {
          id: "i5",
          name: "YKK Zippers (Gold)",
          sku: "RM-ZIP-003",
          category: "Raw Materials",
          qty: 500,
          unit: "pcs",
          threshold: 100,
          cost: 15,
          notes: "Size 5 & 8 mixed.",
        },
      ];
      for (const item of itemsList) {
        await client.query(
          "INSERT INTO items (id, name, sku, category, qty, unit, threshold, unit_cost, notes) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
          [
            item.id,
            item.name,
            item.sku,
            item.category,
            item.qty,
            item.unit,
            item.threshold,
            item.cost || 0,
            item.notes,
          ],
        );
      }
    }
  } catch (err) {
    console.error("Error during database initialization:", err);
  } finally {
    client.release();
  }
}

// Convert SQLite '?' parameters to PostgreSQL '$1, $2, ...'
const convertSql = (sql) => {
  let index = 1;
  return sql.replace(/\?/g, () => `$${index++}`);
};

// Wrapper functions to mimic SQLite3 behavior
const run = async (sql, params = []) => {
  const pgSql = convertSql(sql);
  try {
    const res = await pool.query(pgSql, params);
    // Postgres doesn't provide lastID natively in the same way, but most of our runs don't depend on it.
    // It provides rowCount (number of rows affected).
    return { changes: res.rowCount };
  } catch (err) {
    console.error("DB Run Error:", pgSql, params, err.message);
    throw err;
  }
};

const get = async (sql, params = []) => {
  const pgSql = convertSql(sql);
  try {
    const res = await pool.query(pgSql, params);
    return res.rows[0]; // Returns undefined if no rows
  } catch (err) {
    console.error("DB Get Error:", pgSql, params, err.message);
    throw err;
  }
};

const all = async (sql, params = []) => {
  const pgSql = convertSql(sql);
  try {
    const res = await pool.query(pgSql, params);
    return res.rows;
  } catch (err) {
    console.error("DB All Error:", pgSql, params, err.message);
    throw err;
  }
};

// Only initialize if DATABASE_URL is provided, otherwise let it fail gracefully or log it.
if (process.env.DATABASE_URL) {
  initDb().then(() =>
    console.log("Database initialized successfully with Postgres."),
  );
} else {
  console.error(
    "WARNING: DATABASE_URL is not set. Database initialization skipped.",
  );
}

module.exports = { run, get, all, pool };
