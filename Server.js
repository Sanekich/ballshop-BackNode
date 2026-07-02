require('dotenv').config();

const express = require('express');
const cors = require('cors');
const session = require('express-session');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const { MongoStore } = require('connect-mongo'); // FIX 1: Removed .default to stop the 500 crash

const app = express();

app.use(express.json());
app.set('trust proxy', 1); // Absolutely mandatory for Render to handle HTTPS proxies

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

const MONGO_URI = process.env.MONGO_URI;

mongoose.connect(MONGO_URI)
    .then(() => console.log('Connected to MongoDB successfully.'))
    .catch(err => console.error('MongoDB connection error:', err));

// --- Schemas & Models ---
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true },
    blocked: { type: Number, default: 0 }
}, { timestamps: { createdAt: 'created_at', updatedAt: false } });

const User = mongoose.model('User', userSchema);

const messageSchema = new mongoose.Schema({
    username: { type: String, required: true },
    userEmail: { type: String, required: true },
    message: { type: String }
}, { timestamps: { createdAt: 'created_at', updatedAt: false } });

const Message = mongoose.model('Message', messageSchema);

const orderSchema = new mongoose.Schema({
    customer_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    customer_name: { type: String, required: true },
    customer_surname: { type: String, required: true },
    phone: { type: String, required: true },
    email: { type: String, required: true },
    address: { type: String, required: true },
    city: { type: String, required: true },
    zip: { type: String, required: true },
    cart: { type: Array, required: true },
    total: { type: Number, required: true },
    status: { 
        type: String, 
        enum: ['pending', 'processing', 'shipped', 'completed', 'cancelled'], 
        default: 'pending' 
    }
}, { timestamps: { createdAt: 'created_at', updatedAt: false } });

const Order = mongoose.model('Order', orderSchema);

app.use(session({
    secret: process.env.SESSION_SECRET || 'secret_key',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ // Correct method for modern versions
        mongoUrl: MONGO_URI,
        collectionName: 'sessions'
    }),
    cookie: {
        secure: true, 
        sameSite: 'none', 
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 * 7
    }
}));
// --- API Endpoints ---
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    try {
        if (!username || !email || !password) {
            return res.status(401).json({ error: 'missing fields' });
        }
        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) {
            return res.status(401).json({ error: 'User with this email already exists' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await User.create({
            name: username,
            email: email.toLowerCase(),
            password: hashedPassword
        });
        req.session.user = {
            id: newUser._id,
            name: newUser.name,
            email: newUser.email
        };
        req.session.save((err) => {
            if (err) return res.status(500).json({ error: 'Session error' });
            res.status(200).json({ message: 'Register successful' });
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        if (!email || !password) {
            return res.status(401).json({ error: 'missing fields' });
        }
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(401).json({ error: 'User not found' });
        }
        if (user.blocked === 1) {
            return res.status(401).json({ error: 'User blocked' });
        }
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ error: 'incorrect password' });
        }
        req.session.user = {
            id: user._id,
            name: user.name,
            email: user.email
        };
        req.session.save((err) => {
            if (err) return res.status(500).json({ error: 'Session error' });
            res.status(200).json({ message: 'Login successful' });
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/user', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ loggedIn: false });
    }
    res.json({ loggedIn: true, user: req.session.user });
});

app.post('/api/logout', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ loggedIn: false });
    }
    req.session.destroy((err) => {
        if (err) return res.status(500).json({ error: 'Logout failed' });
        res.clearCookie('connect.sid', { secure: true, sameSite: 'none' });
        res.status(200).json({ message: 'Logged out successfully' });
    });
});

app.post('/api/changeUsername', async (req, res) => {
    const { newName } = req.body;
    if (!req.session.user) {
        return res.status(401).json({ loggedIn: false });
    }
    try {
        const result = await User.updateOne(
            { _id: req.session.user.id },
            { $set: { name: newName } }
        );
        if (result.matchedCount === 0) {
            return res.status(401).json({ error: 'User not found' });
        }
        req.session.user.name = newName;
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
        const users = await User.find({}, 'name email blocked');
        const formattedUsers = users.map(u => ({
            UserId: u._id,
            Name: u.name,
            Email: u.email,
            blocked: u.blocked
        }));
        res.json(formattedUsers);
    } catch (err) {
        console.error('Users query error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/blockUser', async (req, res) => {
    try {
        const { userId } = req.body;
        await User.updateOne({ _id: userId }, { $set: { blocked: 1 } });
        res.json({ message: 'User blocked successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/unblockUser', async (req, res) => {
    try {
        const { userId } = req.body;
        await User.updateOne({ _id: userId }, { $set: { blocked: 0 } });
        res.json({ message: 'User unblocked successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/changeUsername', async (req, res) => {
    try {
        const { userId, newName } = req.body;
        await User.updateOne({ _id: userId }, { $set: { name: newName } });
        res.json({ message: 'Username changed successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/changePassword', async (req, res) => {
    try {
        const { userId, newPassword } = req.body;
        const hashed = await bcrypt.hash(newPassword, 10);
        await User.updateOne({ _id: userId }, { $set: { password: hashed } });
        res.json({ message: 'Password changed successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/deleteUser', async (req, res) => {
    try {
        const { userId } = req.body;
        await User.deleteOne({ _id: userId });
        res.json({ message: 'User deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/order', async (req, res) => {
    const { formData, cart, total } = req.body;
    if (!req.session.user) {
        return res.status(401).json({ error: 'You must be logged in to place an order' });
    }
    try {
        if (!formData || !cart || cart.length === 0 || !total) {
            return res.status(400).json({ error: 'Missing order data' });
        }
        const customerId = req.session.user ? req.session.user.id : null;
        await Order.create({
            customer_id: customerId,
            customer_name: formData.name,
            customer_surname: formData.surname,
            phone: formData.phone,
            email: formData.email,
            address: formData.address,
            city: formData.city,
            zip: formData.zip,
            cart: cart,
            total: total
        });
        res.status(200).json({ message: 'Order placed successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/admin/orders', async (req, res) => {
    try {
        const orders = await Order.find().sort({ created_at: -1 });
        res.json(orders);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/admin/updateOrderStatus', async (req, res) => {
    const { orderId, status } = req.body;
    try {
        const allowedStatuses = ['pending', 'processing', 'shipped', 'completed', 'cancelled'];
        if (!allowedStatuses.includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }
        await Order.updateOne({ _id: orderId }, { $set: { status: status } });
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
        await Message.create({
            username,
            userEmail: email,
            message
        });
        res.status(201).json({ message: 'Sent successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/admin/messages', async (req, res) => {
    try {
        const messages = await Message.find().sort({ created_at: -1 });
        res.json(messages);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});