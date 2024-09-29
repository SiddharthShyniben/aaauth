"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const bcrypt_1 = __importDefault(require("bcrypt"));
const router = express_1.default.Router();
const DEFAULT_CONFIG = {
    userFields: [],
    jwtFields: ['username'],
    jwtSecret: 'THIS_SECRET_IS_NOT_SECURE_AT_ALL',
};
/* TODO:
 * - safer refresh tokens: RTR family
 */
function default_1(config) {
    config = Object.assign(DEFAULT_CONFIG, config);
    // Signup
    router.post('/signup', (req, res) => __awaiter(this, void 0, void 0, function* () {
        if (!['username', 'password', ...config.userFields].every(field => {
            if (!req.body[field]) {
                res.status(400).json({ error: `Missing field: ${field}` });
                return false;
            }
            return true;
        }))
            return;
        const data = accumulateProps(['username', 'password', ...config.userFields], req.body);
        if (yield config.userExists(data)) {
            return res.status(409).json({ error: 'user already exists' });
        }
        data.password = yield bcrypt_1.default.hash(data.password, 10);
        const user = yield config.createUser(data);
        res.status(201).json(user);
    }));
    router.post('/login', (req, res) => __awaiter(this, void 0, void 0, function* () {
        const { username, password } = req.body;
        if (!username)
            return res.status(400).json({ error: 'Missing username' });
        if (!password)
            return res.status(400).json({ error: 'Missing password' });
        if (!(yield config.userExists({ username }))) {
            return res.status(404).json({ error: 'User not found' });
        }
        const user = yield config.getUser({ username });
        if (!(yield bcrypt_1.default.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid password' });
        }
        const jwtData = accumulateProps(['username', ...config.jwtFields], user);
        const accessToken = jsonwebtoken_1.default.sign(jwtData, config.jwtSecret, { expiresIn: '1h' });
        const refreshToken = jsonwebtoken_1.default.sign(jwtData, config.jwtSecret, { expiresIn: '7d' });
        yield config.storeRefreshToken(refreshToken, user);
        yield config.invalidateRefreshToken(refreshToken, user);
        res.status(200).json({ accessToken, refreshToken });
    }));
    router.post('/token', (req, res) => __awaiter(this, void 0, void 0, function* () {
        const { refreshToken: recievedToken } = req.body;
        if (!recievedToken)
            res.status(400).json({ error: 'Missing refreshToken' });
        let decoded;
        try {
            decoded = jsonwebtoken_1.default.verify(recievedToken, config.jwtSecret);
        }
        catch (e) {
            return res.status(401).json({ error: 'Invalid refreshToken' });
        }
        const user = yield config.getUser(decoded); // ??
        if (!user) {
            res.status(404).json({ error: 'User not found' });
        }
        const jwtData = accumulateProps(['username', ...config.jwtFields], user);
        const accessToken = jsonwebtoken_1.default.sign(jwtData, config.jwtSecret, { expiresIn: '1h' });
        const refreshToken = jsonwebtoken_1.default.sign(jwtData, config.jwtSecret, { expiresIn: '7d' });
        yield config.storeRefreshToken(refreshToken, user);
        res.status(200).json({ accessToken, refreshToken });
    }));
    const authenticate = (req, res, next) => __awaiter(this, void 0, void 0, function* () {
        const { accessToken } = req.query;
        if (!accessToken)
            return res.status(400).json({ error: 'Missing accessToken' });
        let decoded;
        try {
            decoded = jsonwebtoken_1.default.verify(accessToken.toString(), config.jwtSecret);
        }
        catch (e) {
            return res.status(401).json({ error: 'Invalid accessToken' });
        }
        const user = yield config.getUser(decoded);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        req.user = user;
        next();
    });
    return { router, authenticate };
}
exports.default = default_1;
function accumulateProps(props, otherObj) {
    return props.reduce((acc, field) => {
        acc[field] = otherObj[field];
        return acc;
    }, {});
}
