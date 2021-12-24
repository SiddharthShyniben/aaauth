import express from 'express';
import Aaauth from './index.js';
const app = express();

const db = {
	users: [],
	refreshTokens: [],
}; // Simple db

const aaauth = Aaauth({
	async createUser(user) {
		db.users.push(user);
	},
	async userExists(user) {
		return !!db.users.find(u => u.username === user.username);
	},
	async getUser(user) {
		return db.users.find(u => u.username === user.username);
	},
	async storeRefreshToken(user, token) {
		db.refreshTokens.push({
			user,
			token
		});
	},
	async refreshTokenExists(user) {
		return db.refreshTokens.find(t => t.user.username === user.username);
	},
	async invalidateRefreshToken(token) {
		db.refreshTokens = db.refreshTokens.filter(t => t.token !== token);
	},
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(aaauth.router);

app.get('/', (req, res) => {
	res.send('Hello World!');
});

app.get('/secure', aaauth.authenticate, (req, res) => {
	res.send('Hello World!');
});

app.listen(3000, () => {
	console.log('Example app listening on port 3000!');
});
