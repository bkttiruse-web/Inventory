require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('./db.js');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'nia_super_secret_key_123';

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Serve the frontend automatically inside /public
app.use(express.static(path.join(__dirname, 'public')));
app.use('/Images', express.static(path.join(__dirname, 'Images')));

// JWT Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

const requireAdmin = async (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        const ts = new Date().toISOString();
        const user = req.user ? req.user.username : 'anonymous';
        await db.run('INSERT INTO audit (ts, event, detail, "user") VALUES (?, ?, ?, ?)', 
            [ts, 'AUTH_FAIL', `Rejected admin access to: ${req.originalUrl}`, user]);
        return res.status(403).json({ error: 'Admins only' });
    }
};

// --- AUTHENTICATION ---
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const ts = new Date().toISOString();
        const user = await db.get('SELECT * FROM users WHERE username = ?', [username.toLowerCase()]);
        
        if (!user) {
            await db.run('INSERT INTO audit (ts, event, detail, "user") VALUES (?, ?, ?, ?)', 
                [ts, 'LOGIN_FAIL', `Non-existent user: ${username}`, 'system']);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const validPassword = await bcrypt.compare(password, user.hash);
        if (!validPassword) {
            await db.run('INSERT INTO audit (ts, event, detail, "user") VALUES (?, ?, ?, ?)', 
                [ts, 'LOGIN_FAIL', `Incorrect password for: ${username}`, username]);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const tokenUser = { id: user.id, username: user.username, role: user.role, name: user.name, initials: user.initials };
        const token = jwt.sign(tokenUser, JWT_SECRET, { expiresIn: '12h' });
        
        await db.run('INSERT INTO audit (ts, event, detail, "user") VALUES (?, ?, ?, ?)', 
            [ts, 'LOGIN_SUCCESS', `User signed in: ${username}`, username]);
            
        res.json({ token, user: tokenUser });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, username, password } = req.body;
        // Strictly ignore role from frontend
        const role = 'staff';
        const ts = new Date().toISOString();

        const exists = await db.get('SELECT * FROM users WHERE username = ?', [username.toLowerCase()]);
        if (exists) {
            return res.status(400).json({ error: 'Username already taken' });
        }
        
        const hash = await bcrypt.hash(password, 10);
        const id = 'u' + Date.now();
        const initials = name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2);
        
        await db.run('INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)', [id, name, username.toLowerCase(), hash, role, initials]);
        
        await db.run('INSERT INTO audit (ts, event, detail, "user") VALUES (?, ?, ?, ?)', 
            [ts, 'USER_REGISTER', `New user registered: ${username}`, username]);

        const tokenUser = { id, username: username.toLowerCase(), role, name, initials };
        const token = jwt.sign(tokenUser, JWT_SECRET, { expiresIn: '12h' });
        
        res.json({ token, user: tokenUser });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Admin Account Recovery / One-Time Setup
app.post('/api/auth/setup-admin', async (req, res) => {
    try {
        const { name, username, password } = req.body;
        const ts = new Date().toISOString();

        // Check if ANY admin exists
        const adminExists = await db.get('SELECT id FROM users WHERE role = \'admin\'');
        if (adminExists) {
            await db.run('INSERT INTO audit (ts, event, detail, "user") VALUES (?, ?, ?, ?)', 
                [ts, 'AUTH_FAIL', 'Blocked setup-admin attempt (admin already exists)', 'system']);
            return res.status(403).json({ error: 'Admin account already exists' });
        }

        const hash = await bcrypt.hash(password, 10);
        const id = 'u' + Date.now();
        const initials = name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2);
        
        await db.run('INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)', [id, name, username.toLowerCase(), hash, 'admin', initials]);
        
        await db.run('INSERT INTO audit (ts, event, detail, "user") VALUES (?, ?, ?, ?)', 
            [ts, 'ADMIN_CREATED', `Root admin created: ${username}`, username]);

        res.json({ success: true, message: 'Admin account created successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Internal error' });
    }
});

// --- ITEMS ---
app.get('/api/items', authenticateToken, async (req, res) => {
    try {
        const isAdmin = req.user.role === 'admin';
        // Only return unit_cost to admins
        let items;
        if (isAdmin) {
            items = await db.all('SELECT * FROM items');
        } else {
            items = await db.all('SELECT id, name, sku, category, qty, unit, threshold, notes FROM items');
        }
        res.json(items);
    } catch (err) {
        res.status(500).json({ error: 'Internal error' });
    }
});

app.post('/api/items', authenticateToken, async (req, res) => {
    try {
        const { name, sku, category, qty, unit, threshold, unit_cost, notes, image_url } = req.body;
        
        // Task #3: Check for duplicate SKU
        const existing = await db.get('SELECT id FROM items WHERE UPPER(sku) = UPPER(?)', [sku]);
        if (existing) {
            return res.status(400).json({ error: 'SKU already exists. Each SKU must be unique.' });
        }
        
        const id = 'i' + Date.now();
        const isAdmin = req.user.role === 'admin';
        
        // Staff cannot set cost
        const actualCost = isAdmin ? (unit_cost || 0) : 0;

        await db.run('INSERT INTO items (id, name, sku, category, qty, unit, threshold, unit_cost, notes, image_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', 
            [id, name, sku, category, qty, unit, threshold, actualCost, notes, image_url || null]);
        
        res.json({ id });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal error' });
    }
});

app.put('/api/items/:id', authenticateToken, async (req, res) => {
    try {
        const { name, sku, category, qty, unit, threshold, unit_cost, notes, image_url } = req.body;
        const isAdmin = req.user.role === 'admin';
        
        if (isAdmin) {
            await db.run(`UPDATE items SET name=?, sku=?, category=?, qty=?, unit=?, threshold=?, unit_cost=?, notes=?, image_url=? WHERE id=?`, 
                [name, sku, category, qty, unit, threshold, unit_cost || 0, notes, image_url || null, req.params.id]);
        } else {
            // Staff cannot update cost
            await db.run(`UPDATE items SET name=?, sku=?, category=?, qty=?, unit=?, threshold=?, notes=?, image_url=? WHERE id=?`, 
                [name, sku, category, qty, unit, threshold, notes, image_url || null, req.params.id]);
        }
        
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Internal error' });
    }
});

app.delete('/api/items/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        await db.run('DELETE FROM items WHERE id=?', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Internal error' });
    }
});

app.post('/api/items/stock', authenticateToken, async (req, res) => {
    try {
        const { item_id, type, amount, notes } = req.body;
        
        // Find item to check category
        const item = await db.get('SELECT * FROM items WHERE id = ?', [item_id]);
        if (!item) return res.status(404).json({ error: 'Item not found' });

        // Restrict manual subtraction for Trim and Fabric
        if (type === 'out' && (item.category === 'Trim' || item.category === 'Fabric')) {
            return res.status(403).json({ error: `Manual subtraction for ${item.category} is not allowed. Please use the Production Report.` });
        }

        const op = type === 'in' ? '+' : '-';
        await db.run(`UPDATE items SET qty = MAX(0, qty ${op} ?) WHERE id = ?`, [amount, item_id]);
        
        const ts = new Date().toISOString();
        const user = req.user ? req.user.username : 'anonymous';
        const detail = `${type === 'in' ? 'Added' : 'Subtracted'} ${amount} for ${item.name}. ${notes || ''}`;
        
        await db.run('INSERT INTO audit (ts, event, detail, "user") VALUES (?, ?, ?, ?)', [ts, 'STOCK_ADJUST', detail, user]);
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal error' });
    }
});

// --- USERS & AUDIT (Admin) ---
app.get('/api/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const users = await db.all('SELECT id, name, username, role, initials FROM users');
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: 'Internal error' });
    }
});

app.put('/api/users/:id/role', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { role } = req.body;
        const ts = new Date().toISOString();
        const adminUser = req.user.username;
        
        const targetUser = await db.get('SELECT username FROM users WHERE id = ?', [req.params.id]);
        if (!targetUser) return res.status(404).json({ error: 'User not found' });

        await db.run('UPDATE users SET role = ? WHERE id = ?', [role, req.params.id]);
        
        await db.run('INSERT INTO audit (ts, event, detail, "user") VALUES (?, ?, ?, ?)', 
            [ts, 'ROLE_CHANGE', `Role of ${targetUser.username} changed to ${role} by admin`, adminUser]);
            
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Internal error' });
    }
});

app.delete('/api/users/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const ts = new Date().toISOString();
        const targetUser = await db.get('SELECT username FROM users WHERE id = ?', [req.params.id]);
        
        await db.run('DELETE FROM users WHERE id=?', [req.params.id]);
        
        if (targetUser) {
            await db.run('INSERT INTO audit (ts, event, detail, "user") VALUES (?, ?, ?, ?)', 
                [ts, 'USER_DELETE', `Deleted user: ${targetUser.username}`, req.user.username]);
        }
        
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Internal error' });
    }
});

app.get('/api/audit', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const logs = await db.all('SELECT * FROM audit WHERE event != \'STOCK_ADJUST\' ORDER BY ts DESC LIMIT 500');
        res.json(logs);
    } catch (err) {
        res.status(500).json({ error: 'Internal error' });
    }
});

app.get('/api/stock-movements', authenticateToken, async (req, res) => {
    try {
        const logs = await db.all('SELECT * FROM audit WHERE event = \'STOCK_ADJUST\' ORDER BY ts DESC LIMIT 500');
        res.json(logs);
    } catch (err) {
        res.status(500).json({ error: 'Internal error' });
    }
});

app.post('/api/audit', authenticateToken, async (req, res) => {
    try {
        const { event, detail } = req.body;
        const ts = new Date().toISOString();
        const user = req.user ? req.user.username : 'anonymous';
        await db.run('INSERT INTO audit (ts, event, detail, "user") VALUES (?, ?, ?, ?)', [ts, event, detail, user]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Internal error' });
    }
});

// --- TRIMS ---
app.get('/api/trims', authenticateToken, async (req, res) => {
    try { 
        const isAdmin = req.user.role === 'admin';
        if (isAdmin) {
            res.json(await db.all('SELECT * FROM trim')); 
        } else {
            res.json(await db.all('SELECT id, item_id, unit_of_measurement, unit_quantity, amount FROM trim'));
        }
    } 
    catch { res.status(500).json({ error: 'Internal error' }); }
});
app.post('/api/trims', authenticateToken, async (req, res) => {
    try {
        const { item_id, unit_of_measurement, unit_quantity, amount, unit_cost } = req.body;
        const id = 't' + Date.now();
        const isAdmin = req.user.role === 'admin';
        const actualCost = isAdmin ? (unit_cost || 0) : 0;
        await db.run('INSERT INTO trim VALUES (?, ?, ?, ?, ?, ?)', [id, item_id, unit_of_measurement, unit_quantity, amount, actualCost]);
        res.json({ id });
    } catch { res.status(500).json({ error: 'Internal error' }); }
});
app.put('/api/trims/:id', authenticateToken, async (req, res) => {
    try {
        const { item_id, unit_of_measurement, unit_quantity, amount, unit_cost } = req.body;
        const isAdmin = req.user.role === 'admin';
        if (isAdmin) {
            await db.run('UPDATE trim SET item_id=?, unit_of_measurement=?, unit_quantity=?, amount=?, unit_cost=? WHERE id=?', [item_id, unit_of_measurement, unit_quantity, amount, unit_cost, req.params.id]);
        } else {
            await db.run('UPDATE trim SET item_id=?, unit_of_measurement=?, unit_quantity=?, amount=? WHERE id=?', [item_id, unit_of_measurement, unit_quantity, amount, req.params.id]);
        }
        res.json({ success: true });
    } catch { res.status(500).json({ error: 'Internal error' }); }
});
app.delete('/api/trims/:id', authenticateToken, async (req, res) => {
    try { await db.run('DELETE FROM trim WHERE id=?', [req.params.id]); res.json({ success: true }); } 
    catch { res.status(500).json({ error: 'Internal error' }); }
});

// --- FABRICS ---
app.get('/api/fabrics', authenticateToken, async (req, res) => {
    try { 
        const isAdmin = req.user.role === 'admin';
        if (isAdmin) {
            res.json(await db.all('SELECT * FROM fabric')); 
        } else {
            res.json(await db.all('SELECT id, fabric_name, consumption FROM fabric'));
        }
    } 
    catch { res.status(500).json({ error: 'Internal error' }); }
});
app.post('/api/fabrics', authenticateToken, async (req, res) => {
    try {
        const { fabric_name, consumption, unit_cost } = req.body;
        const id = 'f' + Date.now();
        const isAdmin = req.user.role === 'admin';
        const actualCost = isAdmin ? (unit_cost || 0) : 0;
        await db.run('INSERT INTO fabric VALUES (?, ?, ?, ?)', [id, fabric_name, consumption, actualCost]);
        res.json({ id });
    } catch { res.status(500).json({ error: 'Internal error' }); }
});
app.put('/api/fabrics/:id', authenticateToken, async (req, res) => {
    try {
        const { fabric_name, consumption, unit_cost } = req.body;
        const isAdmin = req.user.role === 'admin';
        if (isAdmin) {
            await db.run('UPDATE fabric SET fabric_name=?, consumption=?, unit_cost=? WHERE id=?', [fabric_name, consumption, unit_cost, req.params.id]);
        } else {
            await db.run('UPDATE fabric SET fabric_name=?, consumption=? WHERE id=?', [fabric_name, consumption, req.params.id]);
        }
        res.json({ success: true });
    } catch { res.status(500).json({ error: 'Internal error' }); }
});
app.delete('/api/fabrics/:id', authenticateToken, async (req, res) => {
    try { await db.run('DELETE FROM fabric WHERE id=?', [req.params.id]); res.json({ success: true }); } 
    catch { res.status(500).json({ error: 'Internal error' }); }
});

// --- BATCHES ---
app.get('/api/batches', authenticateToken, async (req, res) => {
    try {
        const isAdmin = req.user.role === 'admin';
        const batches = await db.all('SELECT * FROM product_batches ORDER BY created_at DESC');
        for (let b of batches) {
            if (isAdmin) {
                b.materials = await db.all('SELECT * FROM batch_materials WHERE batch_id = ?', [b.id]);
            } else {
                b.materials = await db.all('SELECT id, batch_id, material_id, material_type, consumed_qty FROM batch_materials WHERE batch_id = ?', [b.id]);
            }
            b.stages = await db.all('SELECT * FROM batch_stages WHERE batch_id = ?', [b.id]);
        }
        res.json(batches);
    } catch (err) { res.status(500).json({ error: 'Internal error' }); }
});

app.post('/api/batches', authenticateToken, async (req, res) => {
    try {
        const { product_id, produced_qty, total_duration, materials, stages } = req.body;
        
        // Validate required fields
        if (!product_id || !produced_qty) {
            return res.status(400).json({ error: 'Product and quantity are required' });
        }
        
        const user = req.user ? req.user.username : 'anonymous';
        const created_at = new Date().toISOString();

        // Auto-generate sequential batch number GLOBAL across all products
        const lastBatch = await db.get('SELECT MAX(batch_number) as max_bn FROM product_batches');
        const batch_number = (lastBatch && lastBatch.max_bn ? lastBatch.max_bn : 0) + 1;

        const batch_id = 'b' + Date.now();

        // Look up product name for logging and identification
        // product_id might be an ID or a Name string
        let productItem = await db.get('SELECT * FROM items WHERE id = ? OR name = ? OR sku = ?', [product_id, product_id, product_id]);
        if (!productItem) {
            return res.status(404).json({ error: 'Product not found' });
        }
        const productName = productItem.name;
        const actualProductId = productItem.id;

        await db.run('INSERT INTO product_batches VALUES (?, ?, ?, ?, ?, ?)',
            [batch_id, actualProductId, batch_number, produced_qty, total_duration, created_at]);

        // Increment stock for the product produced
        await db.run('UPDATE items SET qty = qty + ? WHERE id = ?', [produced_qty, productItem.id]);

        // Insert materials + deduct inventory by item ID + log each deduction
        if (materials && Array.isArray(materials)) {
            for (let m of materials) {
                const mId = 'bm' + Math.random().toString(36).substr(2, 9);
                await db.run('INSERT INTO batch_materials VALUES (?, ?, ?, ?, ?, ?, ?)',
                    [mId, batch_id, m.material_id, m.type, m.consumed_qty, m.unit_cost || 0, m.total_cost || 0]);

                // Subtract from items using id
                await db.run('UPDATE items SET qty = MAX(0, qty - ?) WHERE id = ?', [m.consumed_qty, m.material_id]);

                // Log each material deduction
                const matItem = await db.get('SELECT name FROM items WHERE id = ?', [m.material_id]);
                const matName = matItem ? matItem.name : m.material_id;
                const moduleName = m.type === 'trim' ? 'Trim' : 'Fabric';
                await db.run('INSERT INTO audit (ts, event, detail, "user") VALUES (?, ?, ?, ?)',
                    [created_at, `Output | ${moduleName}`,
                     `Consumed ${m.consumed_qty} of ${matName} for Batch #${batch_number} (${productName})`,
                     user]);
            }
        }

        // Insert stages
        if (stages && Array.isArray(stages)) {
            for (let s of stages) {
                const sId = 'bs' + Math.random().toString(36).substr(2, 9);
                await db.run('INSERT INTO batch_stages VALUES (?, ?, ?, ?, ?, ?)',
                    [sId, batch_id, s.stage_name, s.start_date, s.end_date, s.duration]);
            }
        }

        // Log the overall batch creation
        await db.run('INSERT INTO audit (ts, event, detail, "user") VALUES (?, ?, ?, ?)',
            [created_at, 'Entry | Production',
             `New Production Batch #${batch_number} created for ${productName} (Qty: ${produced_qty})`,
             user]);

        res.json({ success: true, batch_id, batch_number });
    } catch (err) {
        console.error('Batch creation error:', err);
        res.status(500).json({ error: err.message || 'Failed to save production batch' });
    }
});

app.post('/api/products/batch', authenticateToken, async (req, res) => {
    // Simplified endpoint purely for adding stock to a product and assigning a batch number automatically
    try {
        const { product_id, produced_qty } = req.body;
        
        // GLOBAL batch number increment
        const lastBatch = await db.get('SELECT MAX(batch_number) as max_bn FROM product_batches');
        const batch_number = (lastBatch && lastBatch.max_bn ? lastBatch.max_bn : 0) + 1;
        
        const batch_id = 'b' + Date.now();
        const created_at = new Date().toISOString();
        
        // Look up item to ensure we have correct ID/SKU
        let productItem = await db.get('SELECT * FROM items WHERE id = ? OR sku = ? OR name = ?', [product_id, product_id, product_id]);
        const actualProductId = productItem ? productItem.id : product_id;

        // Insert a simplified batch with no duration or materials
        await db.run('INSERT INTO product_batches VALUES (?, ?, ?, ?, ?, ?)', [batch_id, actualProductId, batch_number, produced_qty, 'N/A', created_at]);
        
        // Instantly increment the actual stock
        if (productItem) {
            await db.run('UPDATE items SET qty = qty + ? WHERE id = ?', [produced_qty, productItem.id]);
        }
        
        // Log the event
        const user = req.user ? req.user.username : 'anonymous';
        await db.run('INSERT INTO audit (ts, event, detail, "user") VALUES (?, ?, ?, ?)', [created_at, 'STOCK_ADJUST', `Added ${produced_qty} to ${productItem ? productItem.name : product_id} (Batch #${batch_number})`, user]);

        res.json({ success: true, batch_number, batch_id });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal error' });
    }
});

app.delete('/api/batches/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    try { 
        await db.run('DELETE FROM product_batches WHERE id=?', [req.params.id]); 
        await db.run('DELETE FROM batch_materials WHERE batch_id=?', [req.params.id]); 
        await db.run('DELETE FROM batch_stages WHERE batch_id=?', [req.params.id]); 
        res.json({ success: true }); 
    } 
    catch { res.status(500).json({ error: 'Internal error' }); }
});


app.listen(PORT, () => {
    console.log('Server is running on port ' + PORT);
});

module.exports = app;
