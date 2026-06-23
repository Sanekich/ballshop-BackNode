require('dotenv').config();

const express = require('express');
const cors = require('cors');
const session = require('express-session');
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');

const app = express();

app.use(express.json());

// FIXED: Cleaned up origins (removed trailing slash) to resolve CORS block
const allowedOrigins = [
    'http://localhost:3000',
    'https://www.metodo-ballance.it',
    'https://metodo-ballance.it'
];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
}));

app.use(session({
    secret: 'secret_key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true, // Crucial since both Render and your domain use HTTPS
        sameSite: 'none' // Required for cross-domain cookies between Render and your domain
    }
}));

// FIXED: Removed the invalid 'export' keyword
const db = mysql.createPool({
  host: "mysql.railway.internal",
  user: "root",
  password: "HCcLecMajWqUeIWLasyDziwiZLsZrptN",
  database: "railway", 
  port: 3306,
});

app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        if (!username || !email || !password) {
            return res.status(401).json({ error: 'missing fields' });
        }

        const [Users] = await db.query(
            'SELECT * FROM Users WHERE Email = ?',
            [email]
        );

        if (Users.length !== 0) {
            return res.status(401).json({
                error: 'User with this email already exists'
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const [result] = await db.query(
            'INSERT INTO Users (Name, Email, password) VALUES (?, ?, ?)',
            [username, email, hashedPassword]
        );

        req.session.user = {
            id: result.insertId,
            name: username,
            email: email
        };

        req.session.save((err) => {
            if (err) {
                return res.status(500).json({ error: 'Session error' });
            }
            res.status(200).json({ message: 'Register successful' });
        });

    } catch (err) {
        console.error(err);

        res.status(500).json({
            error: 'Internal server error'
        });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        if (!email || !password) {
            return res.status(401).json({
                error: 'missing fields'
            });
        }

        const [Users] = await db.query(
            'SELECT * FROM Users WHERE Email = ?',
            [email]
        );



        if (Users.length === 0) {
            return res.status(401).json({
                error: 'User not found'
            });
        }

        if(Users[0].blocked == 1){
            return res.status(401).json({error: 'User blocked'});
        }

        const match = await bcrypt.compare(
            password,
            Users[0].password
        );

        if (!match) {
            return res.status(401).json({
                error: 'incorrect password'
            });
        }

        req.session.user = {
            id: Users[0].UserId,
            name: Users[0].Name || Users[0].name,
            email: Users[0].Email
        };

        req.session.save((err) => {
            if (err) {
                return res.status(500).json({ error: 'Session error' });
            }
            res.status(200).json({ message: 'Login successful' });
        });

    } catch (err) {
        console.error(err);

        res.status(500).json({
            error: 'Internal server error'
        });
    }
});

app.get('/api/user', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ loggedIn: false });
    }
    res.json({
        loggedIn: true,
        user: req.session.user
    });
});

app.post('/api/logout', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ loggedIn: false });
    }

    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Logout failed' });
        }
        res.clearCookie('connect.sid');
        res.status(200).json({ message: 'Logged out successfully' });
    });
});

app.post('/api/changeUsername', async (req, res) => {
    const { newName } = req.body;

    if (!req.session.user) {
        return res.status(401).json({ loggedIn: false });
    }

    try {
        const [Users] = await db.query(
            'SELECT * FROM Users WHERE Name = ?',
            [req.session.user.name]
        );

        if (Users.length === 0) {
            return res.status(401).json({ error: 'User not found' });
        }

        await db.query(
            'UPDATE Users SET Name = ? WHERE Name = ?',
            [newName, req.session.user.name]
        );

        req.session.user.name = newName;  // update session too

        req.session.save((err) => {
            if (err) return res.status(500).json({ error: 'Session error' });
            res.status(200).json({ message: 'Username updated successfully' });
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/admin/users', async (req, res) => {
    try {
        const [users] = await db.query('SELECT UserId, Name, Email FROM Users');
        res.json(users);
    } catch (err) {
        console.error('Users query error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/blockUser', async (req, res) => {
    try {
        const { userId } = req.body;
        await db.query('UPDATE Users SET blocked = 1 WHERE UserId = ?', [userId]);
        res.json({ message: 'User blocked successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/unblockUser', async (req, res) => {
    try {
        const { userId } = req.body;
        await db.query('UPDATE Users SET blocked = 0 WHERE UserId = ?', [userId]);
        res.json({ message: 'User unblocked successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/changeUsername', async (req, res) => {
    try {
        const { userId, newName } = req.body;
        await db.query('UPDATE Users SET Name = ? WHERE UserId = ?', [newName, userId]);
        res.json({ message: 'Username changed successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/changePassword', async (req, res) => {
    try {
        const { userId, newPassword } = req.body;
        const hashed = await bcrypt.hash(newPassword, 10);
        await db.query('UPDATE Users SET password = ? WHERE UserId = ?', [hashed, userId]);
        res.json({ message: 'Password changed successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/deleteUser', async (req, res) => {
    try {
        const { userId } = req.body;
        await db.query('DELETE FROM Users WHERE UserId = ?', [userId]);
        res.json({ message: 'User deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/order', async (req, res) => {
    const { formData, cart, total } = req.body;

    if (!req.session.user) {
    return res.status(401).json({
        error: 'You must be logged in to place an order'
    });
}

    try {
        if (
            !formData ||
            !cart ||
            cart.length === 0 ||
            !total
        ) {
            return res.status(400).json({
                error: 'Missing order data'
            });
        }

        const customerId = req.session.user
            ? req.session.user.id
            : null;

        await db.query(
            `INSERT INTO orders
            (
                customer_id,
                customer_name,
                customer_surname,
                phone,
                email,
                address,
                city,
                zip,
                cart,
                total
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                customerId,
                formData.name,
                formData.surname,
                formData.phone,
                formData.email,
                formData.address,
                formData.city,
                formData.zip,
                JSON.stringify(cart),
                total
            ]
        );

        res.status(200).json({
            message: 'Order placed successfully'
        });

    } catch (err) {
        console.error(err);

        res.status(500).json({
            error: 'Internal server error'
        });
    }
});

app.get('/api/admin/orders', async (req, res) => {
    try {
        const [orders] = await db.query(
            'SELECT * FROM orders ORDER BY created_at DESC'
        );

        res.json(orders);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/admin/updateOrderStatus', async (req, res) => {
    const { orderId, status } = req.body;

    try {
        const allowedStatuses = [
            'pending',
            'processing',
            'shipped',
            'completed',
            'cancelled'
        ];

        if (!allowedStatuses.includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }

        await db.query(
            'UPDATE orders SET status = ? WHERE id = ?',
            [status, orderId]
        );

        res.json({ message: 'Status updated successfully' });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/sendMessage', async (req, res) => {
    const { username, email, message } = req.body;

    if (!req.session.user) {
        return res.status(401).json({ error: "User not logged in" });
    }

    try {
        await db.query(
            'INSERT INTO Messages (username, userEmail, message) VALUES (?, ?, ?)',
            [username, email, message]
        );

        res.status(201).json({ message: 'Sent successfully' });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/admin/messages', async (req, res) => {
    try {
        const [messages] = await db.query(
            'SELECT id, username, userEmail, message, created_at FROM Messages ORDER BY created_at DESC'
        );

        res.json(messages);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.listen(5000, () => {
    console.log('Server running on port 5000');
});