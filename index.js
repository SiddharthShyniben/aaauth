import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

const router = express.Router();

const DEFAULT_CONFIG = {
	userFields: [],
	jwtFields: ['username'],
	jwtSecret: 'THIS_SECRET_IS_NOT_SECURE_AT_ALL',
	async createUser() {
		throw new Error('createUser must be implemented');
	},
	async userExists(data) {
		throw new Error('userExists must be implemented');
	},
	async userDoesNotExist(data) {
		return !(await this.userExists(data));
	},
	async getUser(data) {
		throw new Error('getUser must be implemented');
	},
	async storeRefreshToken(refreshToken, data) {
		throw new Error('storeRefreshToken must be implemented');
	},
	async refreshTokenExists(refreshToken) {
		throw new Error('refreshTokenExists must be implemented');
	},
	async invalidateRefreshToken(refreshToken) {
		throw new Error('invalidateRefreshToken must be implemented');
	},
};

/* TODO:
 * - safer refresh tokens: RTR family
 */

export default function (config) {
	config = Object.assign(DEFAULT_CONFIG, config);

	// Signup
	router.post('/signup', async (req, res) => {
		let shouldBreak = false;
		['username', 'password', ...config.userFields].every(field => {
			if (!req.body[field]) {
				res.status(400).json({
					error: `Missing field: ${field}`
				});
				return false;
				shouldBreak = true;
			}
			return true;
		});

		if (shouldBreak) {
			return;
		}

		const data = ['username', 'password', ...config.userFields].reduce((acc, field) => {
			acc[field] = req.body[field];
			return acc;
		}, {});

		if (await config.userExists(data)) {
			return res.status(409).json({
				error: 'user already exists'
			});
		}

		console.log(data);
		data.password = await bcrypt.hash(data.password, 10);

		const user = await config.createUser(data);
		res.status(201).json(user);
	});

	router.post('/login', async (req, res) => {
		const {username, password} = req.body;

		if (!username) return res.status(400).json({error: 'Missing username'});
		if (!password) return res.status(400).json({error: 'Missing password'});

		if (await config.userDoesNotExist({username})) {
			return res.status(404).json({error: 'User not found'});
		}

		const user = await config.getUser({username});

		if (!(await bcrypt.compare(password, user.password))) {
			return res.status(401).json({error: 'Invalid password'});
		}

		const jwtData = ['username', ...config.jwtFields].reduce((acc, field) => {
			acc[field] = user[field];
			return acc;
		}, {});

		const accessToken = jwt.sign(jwtData, config.jwtSecret, {expiresIn: '1h'});
		const refreshToken = jwt.sign(jwtData, config.jwtSecret, {expiresIn: '7d'});
		await config.storeRefreshToken(refreshToken, user);

		res.status(200).json({accessToken, refreshToken});
	});

	router.post('/token', async (req, res) => {
		const {refreshToken: recievedToken} = req.body;

		if (!recievedToken) res.status(400).json({error: 'Missing refreshToken'});

		let decoded;

		try {
			decoded = jwt.verify(recievedToken, config.jwtSecret);
		} catch (e) {
			res.status(401).json({error: 'Invalid refreshToken'});
		}

		const user = await config.getUser(decoded);

		if (!user) {
			res.status(404).json({error: 'User not found'});
		}

		const jwtData = ['username', ...config.jwtFields].reduce((acc, field) => {
			acc[field] = user[field];
			return acc;
		}, {});

		const accessToken = jwt.sign(jwtData, config.jwtSecret, {expiresIn: '1h'});
		const refreshToken = jwt.sign(jwtData, config.jwtSecret, {expiresIn: '7d'});
		await config.storeRefreshToken(refreshToken, user);

		res.status(200).json({accessToken, refreshToken});
	});

	const authenticate = async (req, res, next) => {
		console.log(req.query);
		const {accessToken} = req.query;

		if (!accessToken) return res.status(400).json({error: 'Missing accessToken'});

		let decoded;

		try {
			decoded = jwt.verify(accessToken, config.jwtSecret);
		} catch (e) {
			return res.status(401).json({error: 'Invalid accessToken'});
		}

		const user = await config.getUser(decoded);

		if (!user) {
			return res.status(404).json({error: 'User not found'});
		}

		req.user = user;
		next();
	};

	return {router, authenticate};
}
