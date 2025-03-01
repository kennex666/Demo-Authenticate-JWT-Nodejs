const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');

const fs = require('fs');
const app = express();
app.use(express.json());

// Schema MongoDB
mongoose.connect('mongodb://localhost:27017/authDB', {
	useNewUrlParser: true,
	useUnifiedTopology: true,
});

const UserSchema = new mongoose.Schema({
	username: String,
	password: String,
	role: String
});

const User = mongoose.model('User', UserSchema);

// Config
const TIME_RF_EXPIRED = '7d';
const TIME_AT_EXPIRED = '30m';

const PRIVATE_KEY = fs.readFileSync("./storages/jwtRSA256-private.pem", "utf8");
const PUBLIC_KEY = fs.readFileSync("./storages/jwtRSA256-public.pem", "utf8");

// Đăng ký
app.post('/register', async (req, res) => {
	const { username, password, role } = req.body;
	const hashedPassword = await bcrypt.hash(password, 10);
	
	const isExist = await User.findOne({ username });
	if (isExist){
		return res.json({ message: 'User already exists' });
	}
	const user = new User({ username, password: hashedPassword, role });
	await user.save();
	res.json({ message: 'User registered', data: user });
});

// Đăng nhập
app.post('/login', async (req, res) => {
	const { username, password } = req.body;
	const user = await User.findOne({ username });
	if (!user || !(await bcrypt.compare(password, user.password))) {
		return res.status(401).json({ message: 'Invalid credentials' });
	}

	const token = jwt.sign({ userId: user._id, role: user.role }, PRIVATE_KEY, {
		algorithm: "RS256",
		expiresIn: TIME_AT_EXPIRED,
	});

	// refresh token
	const refreshToken = jwt.sign({ userId: user._id, role: user.role }, PRIVATE_KEY, {
		algorithm: "RS256",
		expiresIn: TIME_RF_EXPIRED,
	});
	res.json({ accessToken: token, refreshToken });
});

// Refresh token
app.post('/refresh-token', (req, res) => {
	const { refreshToken } = req.body;
	if (!refreshToken) {
		return res.status(401).json({ message: 'Access denied' });
	}
	
	try {
		const decoded = jwt.verify(refreshToken, PUBLIC_KEY, {
			algorithm: "RS256",
		});
		// check token hết hạn hay chưa
		if (Date.now() >= decoded.exp * 1000) {
			return res.status(401).json({ message: "Token expired" });
		}

		const token = jwt.sign(
			{ userId: decoded.userId, role: decoded.role },
			PRIVATE_KEY,
			{
				algorithm: "RS256",
				expiresIn: TIME_AT_EXPIRED,
			}
		);
		res.json({ accessToken: token });
	} catch (err) {
		res.status(400).json({ message: 'Invalid token' });
	}
});

// Middleware để check jwt
const authMiddleware = (req, res, next) => {
	let token = req.header('Authorization');
	
	token = token && token.startsWith('Bearer ') ? token.slice(7) : null;

	if (!token) return res.status(401).json({ message: 'Access denied' });
	try {
		const decoded = jwt.verify(token, PUBLIC_KEY, {
			algorithm: "RS256",
		});
		// check token hết hạn hay chưa
		if (Date.now() >= decoded.exp * 1000) {
			return res.status(401).json({ message: 'Token expired' });
		}
		req.user = decoded;
		next();
	} catch (err) {
		res.status(400).json({ message: 'Invalid token' });
	}
};

// Route cần auth (Miễn là đã login)
app.get('/protected', authMiddleware, (req, res) => {
	res.json({ message: 'This is a protected route', userId: req.user.userId, rawData: req.user });
});

// Route lấy full data user
app.get('/user', authMiddleware, async (req, res) => {
	const user = await User.findById(req.user.userId);
	res.json({message: 'This is a protected route', user });
});

// Route chỉ auth cho admin
app.get('/admin', authMiddleware, (req, res) => {
	if (req.user.role !== 'admin') {
		return res.status(403).json({ message: 'Access denied - Only for admin' });
	}
	
	res.json({ message: 'This is an admin route', userId: req.user.userId });
});

// Ai cũng xem được
app.get('/', (req, res) => {
	res.send('Hello World');
});

app.listen(3000, () => console.log('Server running on port 3000'));
