const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

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
	async storeRefreshToken(data, refreshToken) {
		throw new Error('storeRefreshToken must be implemented');
	},
};

/* TODO:
 * - safer refresh tokens: RTR family
 */

export default function (config) {
	config = Object.assign(DEFAULT_CONFIG, config);

	// Signup
	router.post('/signup', (req, res) => {
		config.userFields.forEach(field => {
			if (!req.body[field]) {
				res.status(400).json({
					error: `Missing field: ${field}`
				});
			}
		});

		const data = ['username', 'password', ...config.userFields].reduce((acc, field) => {
			acc[field] = req.body[field];
			return acc;
		}, {});

		if (await config.userExists(data)) {
			res.status(409).json({
				error: 'user already exists'
			});
		}

		data.password = await bcrypt.hash(data.password, 10);

		const user = await config.createUser(data);
		res.status(201).json(user);
	});

	router.post('/login', (req, res) => {
		const {username, password} = req.body;

		if (!username) res.status(400).json({error: 'Missing username'});
		if (!password) res.status(400).json({error: 'Missing password'});

		if (await config.userDoesNotExist({username})) {
			res.status(404).json({error: 'User not found'});
		}

		const user = await config.getUser({username});

		if (!(await bcrypt.compare(password, user.password))) {
			res.status(401).json({error: 'Invalid password'});
		}

		const jwtData = ['username', ...config.jwtFields].reduce((acc, field) => {
			acc[field] = user[field];
			return acc;
		}, {});

		const accessToken = jwt.sign(jwtData, config.jwtSecret, {expiresIn: '1h'});
		const refreshToken = jwt.sign(jwtData, config.jwtSecret, {expiresIn: '7d'});
		await storeRefreshToken(refreshToken, user);

		res.status(200).json({accessToken, refreshToken});
	});

	router.post('/token', (req, res) => {
		const {refreshToken} = req.body;

		if (!refreshToken) res.status(400).json({error: 'Missing refreshToken'});

		let decoded;

		try {
			decoded = jwt.verify(refreshToken, config.jwtSecret);
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
		await storeRefreshToken(refreshToken, user);

		res.status(200).json({accessToken, refreshToken});
	});
}
