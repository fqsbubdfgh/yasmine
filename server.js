const express = require('express');
const fs = require('fs');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3001;
const DB_FILE = __dirname + '/db.json';
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'vision_secret_2025';

app.use(cors());
app.use(express.json());

// Helper to read/write DB
function readDB() {
    if (!fs.existsSync(DB_FILE)) {
        // Initialize with empty products array
        fs.writeFileSync(DB_FILE, JSON.stringify({ 
            orders: [], 
            products: [],
            stocks: { /* existing stock structure */ }
        }, null, 2));
    }
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}
function writeDB(data) {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// Get stocks
app.get('/api/stocks', (req, res) => {
    const db = readDB();
    res.json(db.stocks);
});

// Set stocks (admin)
app.post('/api/stocks', (req, res) => {
    const db = readDB();
    db.stocks = req.body;
    writeDB(db);
    res.json({ success: true });
});

// Get orders
app.get('/api/orders', (req, res) => {
    const db = readDB();
    res.json(db.orders);
});

// Add order
app.post('/api/orders', (req, res) => {
    const db = readDB();
    db.orders.push(req.body);
    // Optionally update stocks here if order contains cart
    if (req.body.cart) {
        req.body.cart.forEach(item => {
            if (item.type === 'tshirt') {
                const { style, size } = item;
                if (db.stocks.tshirt?.[style]?.[size] > 0) {
                    db.stocks.tshirt[style][size]--;
                }
            }
            if (item.type === 'jort') {
                const { size } = item;
                if (db.stocks.jort?.[size] > 0) {
                    db.stocks.jort[size]--;
                }
            }
        });
    }
    writeDB(db);
    res.json({ success: true });
});

// Delete order (admin)
app.delete('/api/orders/:index', (req, res) => {
    const db = readDB();
    const idx = parseInt(req.params.index, 10);
    if (idx >= 0 && idx < db.orders.length) {
        db.orders.splice(idx, 1);
        writeDB(db);
        res.json({ success: true });
    } else {
        res.status(404).json({ error: 'Order not found' });
    }
});

// Get all products
app.get('/api/products', (req, res) => {
    const db = readDB();
    res.json(db.products || []);
});

// Create/update product
app.post('/api/products', (req, res) => {
    const db = readDB();
    const product = req.body;

    // Basic validation
    if (!product.name || typeof product.price !== 'number' || !product.type) {
        return res.status(400).json({ success: false, error: 'Invalid product data' });
    }

    db.products = db.products || [];

    // If id is missing or empty, create new product
    if (!product.id || product.id === '') {
        product.id = crypto.randomBytes(4).toString('hex');
        db.products.push(product);
        writeDB(db);
        return res.json({ success: true, id: product.id });
    } else {
        // Update existing product
        const index = db.products.findIndex(p => p.id === product.id);
        if (index !== -1) {
            db.products[index] = product;
            writeDB(db);
            return res.json({ success: true, id: product.id });
        } else {
            return res.status(404).json({ success: false, error: 'Product not found' });
        }
    }
});

// Delete product
app.delete('/api/products/:id', (req, res) => {
    const db = readDB();
    const initialLength = (db.products || []).length;
    db.products = (db.products || []).filter(p => p.id !== req.params.id);
    writeDB(db);
    if (db.products.length < initialLength) {
        res.json({ success: true });
    } else {
        res.status(404).json({ success: false, error: 'Product not found' });
    }
});

// --- JWT Auth Middleware ---
function requireAdmin(req, res, next) {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
    try {
        jwt.verify(auth.slice(7), JWT_SECRET);
        next();
    } catch (e) {
        res.status(401).json({ error: 'Invalid token' });
    }
}

// --- Admin Login ---
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    const db = readDB();
    if (db.admin && username === db.admin.username && password === db.admin.password) {
        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '2h' });
        return res.json({ success: true, token });
    }
    res.status(401).json({ success: false, error: 'Invalid credentials' });
});

// --- Change Admin Credentials ---
app.post('/api/admin/change-credentials', requireAdmin, (req, res) => {
    const { username, password } = req.body;
    if (!username || !password || username.length < 3 || password.length < 4) {
        return res.status(400).json({ success: false, error: 'Invalid username or password' });
    }
    const db = readDB();
    db.admin = { username, password };
    writeDB(db);
    res.json({ success: true });
});

// --- Protect admin endpoints ---
app.post('/api/products', requireAdmin, (req, res) => {
    const db = readDB();
    const product = req.body;

    // Basic validation
    if (!product.name || typeof product.price !== 'number' || !product.type) {
        return res.status(400).json({ success: false, error: 'Invalid product data' });
    }

    db.products = db.products || [];

    // If id is missing or empty, create new product
    if (!product.id || product.id === '') {
        product.id = crypto.randomBytes(4).toString('hex');
        db.products.push(product);
        writeDB(db);
        return res.json({ success: true, id: product.id });
    } else {
        // Update existing product
        const index = db.products.findIndex(p => p.id === product.id);
        if (index !== -1) {
            db.products[index] = product;
            writeDB(db);
            return res.json({ success: true, id: product.id });
        } else {
            return res.status(404).json({ success: false, error: 'Product not found' });
        }
    }
});
app.delete('/api/products/:id', requireAdmin, (req, res) => {
    const db = readDB();
    const initialLength = (db.products || []).length;
    db.products = (db.products || []).filter(p => p.id !== req.params.id);
    writeDB(db);
    if (db.products.length < initialLength) {
        res.json({ success: true });
    } else {
        res.status(404).json({ success: false, error: 'Product not found' });
    }
});
app.post('/api/stocks', requireAdmin, (req, res) => {
    const db = readDB();
    db.stocks = req.body;
    writeDB(db);
    res.json({ success: true });
});
app.delete('/api/orders/:index', requireAdmin, (req, res) => {
    const db = readDB();
    const idx = parseInt(req.params.index, 10);
    if (idx >= 0 && idx < db.orders.length) {
        db.orders.splice(idx, 1);
        writeDB(db);
        res.json({ success: true });
    } else {
        res.status(404).json({ error: 'Order not found' });
    }
});

app.listen(PORT, () => {
    console.log(`Backend running on port ${PORT}`);
});