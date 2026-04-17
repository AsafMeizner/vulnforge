import { Router, type Request, type Response } from 'express';
import {
  getUsers,
  getUserById,
  createUser,
  updateUser,
  deleteUser,
  countUsers,
  createApiToken,
  getApiTokensByUser,
  deleteApiToken,
} from '../db.js';
import {
  hashPassword,
  login,
  generateToken,
  setupInitialUser,
  type AuthenticatedRequest,
  requireRole,
} from '../auth/auth.js';

const router = Router();

// ── POST /api/auth/setup - initial admin user creation ───────────────────

router.post('/setup', async (req: Request, res: Response) => {
  try {
    const userCount = countUsers();
    if (userCount > 0) {
      res.status(409).json({ error: 'Users already exist. Use /login instead.' });
      return;
    }
    const { username, password } = req.body;
    if (!username || !password) {
      res.status(400).json({ error: 'username and password required' });
      return;
    }
    if (password.length < 6) {
      res.status(400).json({ error: 'password must be at least 6 characters' });
      return;
    }
    const user = await setupInitialUser(username, password);
    if (!user) { res.status(500).json({ error: 'Failed to create user' }); return; }

    // Generate an API token for the new admin
    const token = generateToken();
    createApiToken({ user_id: user.id!, token, name: 'initial-setup' });

    res.status(201).json({
      user: { id: user.id, username: user.username, role: user.role },
      token,
      message: 'Admin user created. Save your API token.',
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/auth/login - authenticate and get token ────────────────────

router.post('/login', async (req: Request, res: Response) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      res.status(400).json({ error: 'username and password required' });
      return;
    }

    const user = await login(username, password);
    if (!user) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    // Generate a session token
    const token = generateToken();
    createApiToken({ user_id: user.id!, token, name: 'login-session' });

    res.json({
      user: { id: user.id, username: user.username, role: user.role, display_name: user.display_name },
      token,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/auth/me - current user info ─────────────────────────────────

router.get('/me', (req: AuthenticatedRequest, res: Response) => {
  res.json({ user: req.user || null, multi_user: countUsers() > 0 });
});

// ── GET /api/auth/status - auth system status ────────────────────────────

router.get('/status', (_req: Request, res: Response) => {
  try {
    const userCount = countUsers();
    res.json({
      setup_required: userCount === 0,
      multi_user: userCount > 0,
      user_count: userCount,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ── User management (admin only) ─────────────────────────────────────────

router.get('/users', requireRole('admin'), (_req: Request, res: Response) => {
  try {
    const users = getUsers();
    res.json({ data: users, total: users.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/users', requireRole('admin'), async (req: Request, res: Response) => {
  try {
    const { username, password, role, display_name, email } = req.body;
    if (!username || !password) { res.status(400).json({ error: 'username and password required' }); return; }
    const hash = await hashPassword(password);
    const id = createUser({
      username,
      password_hash: hash,
      role: role || 'researcher',
      display_name,
      email,
    });
    res.status(201).json(getUserById(id));
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.put('/users/:id', requireRole('admin'), (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    updateUser(id, req.body);
    res.json(getUserById(id));
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.delete('/users/:id', requireRole('admin'), (req: Request, res: Response) => {
  try {
    deleteUser(Number(req.params.id));
    res.json({ deleted: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ── Token management ─────────────────────────────────────────────────────

router.get('/tokens', (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user?.id) { res.json({ data: [] }); return; }
    const tokens = getApiTokensByUser(req.user.id);
    // Mask token values for display
    const masked = tokens.map(t => ({
      ...t,
      token: t.token.slice(0, 8) + '...',
    }));
    res.json({ data: masked, total: masked.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/tokens', (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user?.id) { res.status(401).json({ error: 'Not authenticated' }); return; }
    const token = generateToken();
    const id = createApiToken({
      user_id: req.user.id,
      token,
      name: req.body?.name || 'api-token',
      expires_at: req.body?.expires_at,
    });
    res.status(201).json({ id, token, message: 'Save this token - it will not be shown again.' });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.delete('/tokens/:id', (req: AuthenticatedRequest, res: Response) => {
  try {
    deleteApiToken(Number(req.params.id));
    res.json({ deleted: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

export default router;
