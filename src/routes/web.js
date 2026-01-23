const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const redis = require('../models/redis');
const logger = require('../utils/logger');
const config = require('../../config/config');

const router = express.Router();

// 🏠 服务静态文件
router.use('/assets', express.static(path.join(__dirname, '../../web/assets')));

// 🔒 Web管理界面文件白名单 - 仅允许这些特定文件
const ALLOWED_FILES = {
  'index.html': {
    path: path.join(__dirname, '../../web/admin/index.html'),
    contentType: 'text/html; charset=utf-8'
  },
  'app.js': {
    path: path.join(__dirname, '../../web/admin/app.js'),
    contentType: 'application/javascript; charset=utf-8'
  },
  'style.css': {
    path: path.join(__dirname, '../../web/admin/style.css'),
    contentType: 'text/css; charset=utf-8'
  }
};

// 🛡️ 安全文件服务函数
function serveWhitelistedFile(req, res, filename) {
  const fileConfig = ALLOWED_FILES[filename];
  
  if (!fileConfig) {
    logger.security(`🚨 Attempted access to non-whitelisted file: ${filename}`);
    return res.status(404).json({ error: 'File not found' });
  }

  try {
    // 检查文件是否存在
    if (!fs.existsSync(fileConfig.path)) {
      logger.error(`❌ Whitelisted file not found: ${fileConfig.path}`);
      return res.status(404).json({ error: 'File not found' });
    }

    // 读取并返回文件内容
    const content = fs.readFileSync(fileConfig.path, 'utf8');
    res.setHeader('Content-Type', fileConfig.contentType);
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.send(content);
    
    logger.info(`📄 Served whitelisted file: ${filename}`);
  } catch (error) {
    logger.error(`❌ Error serving file ${filename}:`, error);
    res.status(500).json({ error: 'Internal server error' });
  }
}

// 🔐 管理员登录
router.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        error: 'Missing credentials',
        message: 'Username and password are required'
      });
    }

    // 从Redis获取管理员信息
    const adminData = await redis.getSession('admin_credentials');
    
    if (!adminData || Object.keys(adminData).length === 0) {
      return res.status(401).json({
        error: 'Invalid credentials',
        message: 'Invalid username or password'
      });
    }

    // 验证用户名和密码
    const isValidUsername = adminData.username === username;
    const isValidPassword = await bcrypt.compare(password, adminData.passwordHash);

    if (!isValidUsername || !isValidPassword) {
      logger.security(`🔒 Failed login attempt for username: ${username}`);
      return res.status(401).json({
        error: 'Invalid credentials',
        message: 'Invalid username or password'
      });
    }

    // 生成会话token
    const sessionId = crypto.randomBytes(32).toString('hex');
    
    // 存储会话
    const sessionData = {
      username: adminData.username,
      loginTime: new Date().toISOString(),
      lastActivity: new Date().toISOString()
    };
    
    await redis.setSession(sessionId, sessionData, config.security.adminSessionTimeout);
    
    // 更新最后登录时间
    adminData.lastLogin = new Date().toISOString();
    await redis.setSession('admin_credentials', adminData);

    logger.success(`🔐 Admin login successful: ${username}`);

    res.json({
      success: true,
      token: sessionId,
      expiresIn: config.security.adminSessionTimeout
    });

  } catch (error) {
    logger.error('❌ Login error:', error);
    res.status(500).json({
      error: 'Login failed',
      message: 'Internal server error'
    });
  }
});

// 🚪 管理员登出
router.post('/auth/logout', async (req, res) => {
  try {
    const token = req.headers['authorization']?.replace('Bearer ', '') || req.cookies?.adminToken;
    
    if (token) {
      await redis.deleteSession(token);
      logger.success('🚪 Admin logout successful');
    }

    res.json({ success: true, message: 'Logout successful' });
  } catch (error) {
    logger.error('❌ Logout error:', error);
    res.status(500).json({
      error: 'Logout failed',
      message: 'Internal server error'
    });
  }
});

// 🔄 刷新token
router.post('/auth/refresh', async (req, res) => {
  try {
    const token = req.headers['authorization']?.replace('Bearer ', '') || req.cookies?.adminToken;
    
    if (!token) {
      return res.status(401).json({
        error: 'No token provided',
        message: 'Authentication required'
      });
    }

    const sessionData = await redis.getSession(token);
    
    if (!sessionData) {
      return res.status(401).json({
        error: 'Invalid token',
        message: 'Session expired or invalid'
      });
    }

    // 更新最后活动时间
    sessionData.lastActivity = new Date().toISOString();
    await redis.setSession(token, sessionData, config.security.adminSessionTimeout);

    res.json({
      success: true,
      token: token,
      expiresIn: config.security.adminSessionTimeout
    });

  } catch (error) {
    logger.error('❌ Token refresh error:', error);
    res.status(500).json({
      error: 'Token refresh failed',
      message: 'Internal server error'
    });
  }
});

// 🌐 Web管理界面路由 - 使用固定白名单
router.get('/', (req, res) => {
  serveWhitelistedFile(req, res, 'index.html');
});

router.get('/app.js', (req, res) => {
  serveWhitelistedFile(req, res, 'app.js');
});

router.get('/style.css', (req, res) => {
  serveWhitelistedFile(req, res, 'style.css');
});

module.exports = router;