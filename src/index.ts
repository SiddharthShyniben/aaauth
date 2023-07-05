import express from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';
import bcrypt from 'bcrypt';

const router = express.Router();

type User = {
	username: string,
	password: string,
	[key: string]: any,
}

type Config = {
	userFields: string[],
	jwtFields: string[],
	jwtSecret: string,
	createUser: (user: User) => Promise<User>,
	userExists: (user: Partial<User>) => Promise<boolean>,
	getUser: (user: Partial<User>) => Promise<User>,
	storeRefreshToken: (token: string, user: User) => Promise<void>,
	refreshTokenExists: (user: User) => Promise<boolean>,
	invalidateRefreshToken: (token: string) => Promise<void>,
}

const DEFAULT_CONFIG: Partial<Config> = {
	userFields: [],
	jwtFields: ['username'],
	jwtSecret: 'THIS_SECRET_IS_NOT_SECURE_AT_ALL',
};

/* TODO:
 * - safer refresh tokens: RTR family
 */

export default function (config: Config) {
	config = Object.assign(DEFAULT_CONFIG, config);

	// Signup
	router.post('/signup', async (req, res) => {
		if (!['username', 'password', ...config.userFields].every(field => {
			if (!req.body[field]) {
				res.status(400).json({
					error: `Missing field: ${field}`
				});
				return false;
			}
			return true;
		})) return;

		const data = ['username', 'password', ...config.userFields].reduce((acc: Partial<User>, field: string) => {
			acc[field] = req.body[field];
			return acc;
		}, {}) as User;

		if (await config.userExists(data)) {
			return res.status(409).json({error: 'user already exists'});
		}

		data.password = await bcrypt.hash(data.password, 10);

		const user = await config.createUser(data);
		res.status(201).json(user);
	});

	router.post('/login', async (req, res) => {
		const {username, password} = req.body;

		if (!username) return res.status(400).json({error: 'Missing username'});
		if (!password) return res.status(400).json({error: 'Missing password'});

		if (!(await config.userExists({username}))) {
			return res.status(404).json({error: 'User not found'});
		}

		const user = await config.getUser({username});

		if (!(await bcrypt.compare(password, user.password))) {
			return res.status(401).json({error: 'Invalid password'});
		}

		const jwtData = ['username', ...config.jwtFields].reduce((acc: Partial<User>, field) => {
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
			return res.status(401).json({error: 'Invalid refreshToken'});
		}

		const user = await config.getUser(decoded as JwtPayload); // ??

		if (!user) {
			res.status(404).json({error: 'User not found'});
		}

		const jwtData = ['username', ...config.jwtFields].reduce((acc: Partial<User>, field) => {
			acc[field] = user[field];
			return acc;
		}, {});

		const accessToken = jwt.sign(jwtData, config.jwtSecret, {expiresIn: '1h'});
		const refreshToken = jwt.sign(jwtData, config.jwtSecret, {expiresIn: '7d'});
		await config.storeRefreshToken(refreshToken, user);

		res.status(200).json({accessToken, refreshToken});
	});

	const authenticate = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
		const {accessToken} = req.query;

		if (!accessToken) return res.status(400).json({error: 'Missing accessToken'});

		let decoded;

		try {
			decoded = jwt.verify(accessToken.toString(), config.jwtSecret);
		} catch (e) {
			return res.status(401).json({error: 'Invalid accessToken'});
		}

		const user = await config.getUser(decoded as JwtPayload);

		if (!user) {
			return res.status(404).json({error: 'User not found'});
		}

		(req as any).user = user;
		next();
	};

	return {router, authenticate};
}
