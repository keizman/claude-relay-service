const express = require('express');
const apiKeyService = require('../services/apiKeyService');
const claudeAccountService = require('../services/claudeAccountService');
const redis = require('../models/redis');
const { authenticateAdmin } = require('../middleware/auth');
const logger = require('../utils/logger');
const oauthHelper = require('../utils/oauthHelper');
const CostCalculator = require('../utils/costCalculator');
const pricingService = require('../services/pricingService');

const router = express.Router();

// 🔑 API Keys 管理

// 获取所有API Keys
router.get('/api-keys', authenticateAdmin, async (req, res) => {
  try {
    const apiKeys = await apiKeyService.getAllApiKeys();
    res.json({ success: true, data: apiKeys });
  } catch (error) {
    logger.error('❌ Failed to get API keys:', error);
    res.status(500).json({ error: 'Failed to get API keys', message: error.message });
  }
});

// 创建新的API Key
router.post('/api-keys', authenticateAdmin, async (req, res) => {
  try {
    const {
      name,
      description,
      tokenLimit,
      expiresAt,
      claudeAccountId,
      concurrencyLimit,
      rateLimitWindow,
      rateLimitRequests,
      enableModelRestriction,
      restrictedModels
    } = req.body;

    // 输入验证
    if (!name || typeof name !== 'string' || name.trim().length === 0) {
      return res.status(400).json({ error: 'Name is required and must be a non-empty string' });
    }

    if (name.length > 100) {
      return res.status(400).json({ error: 'Name must be less than 100 characters' });
    }

    if (description && (typeof description !== 'string' || description.length > 500)) {
      return res.status(400).json({ error: 'Description must be a string with less than 500 characters' });
    }

    if (tokenLimit && (!Number.isInteger(Number(tokenLimit)) || Number(tokenLimit) < 0)) {
      return res.status(400).json({ error: 'Token limit must be a non-negative integer' });
    }


    if (concurrencyLimit !== undefined && concurrencyLimit !== null && concurrencyLimit !== '' && (!Number.isInteger(Number(concurrencyLimit)) || Number(concurrencyLimit) < 0)) {
      return res.status(400).json({ error: 'Concurrency limit must be a non-negative integer' });
    }
    
    if (rateLimitWindow !== undefined && rateLimitWindow !== null && rateLimitWindow !== '' && (!Number.isInteger(Number(rateLimitWindow)) || Number(rateLimitWindow) < 1)) {
      return res.status(400).json({ error: 'Rate limit window must be a positive integer (minutes)' });
    }
    
    if (rateLimitRequests !== undefined && rateLimitRequests !== null && rateLimitRequests !== '' && (!Number.isInteger(Number(rateLimitRequests)) || Number(rateLimitRequests) < 1)) {
      return res.status(400).json({ error: 'Rate limit requests must be a positive integer' });
    }

    // 验证模型限制字段
    if (enableModelRestriction !== undefined && typeof enableModelRestriction !== 'boolean') {
      return res.status(400).json({ error: 'Enable model restriction must be a boolean' });
    }

    if (restrictedModels !== undefined && !Array.isArray(restrictedModels)) {
      return res.status(400).json({ error: 'Restricted models must be an array' });
    }

    const newKey = await apiKeyService.generateApiKey({
      name,
      description,
      tokenLimit,
      expiresAt,
      claudeAccountId,
      concurrencyLimit,
      rateLimitWindow,
      rateLimitRequests,
      enableModelRestriction,
      restrictedModels
    });

    logger.success(`🔑 Admin created new API key: ${name}`);
    res.json({ success: true, data: newKey });
  } catch (error) {
    logger.error('❌ Failed to create API key:', error);
    res.status(500).json({ error: 'Failed to create API key', message: error.message });
  }
});

// 更新API Key
router.put('/api-keys/:keyId', authenticateAdmin, async (req, res) => {
  try {
    const { keyId } = req.params;
    const { tokenLimit, concurrencyLimit, rateLimitWindow, rateLimitRequests, claudeAccountId, enableModelRestriction, restrictedModels } = req.body;

    // 只允许更新指定字段
    const updates = {};
    
    if (tokenLimit !== undefined && tokenLimit !== null && tokenLimit !== '') {
      if (!Number.isInteger(Number(tokenLimit)) || Number(tokenLimit) < 0) {
        return res.status(400).json({ error: 'Token limit must be a non-negative integer' });
      }
      updates.tokenLimit = Number(tokenLimit);
    }

    if (concurrencyLimit !== undefined && concurrencyLimit !== null && concurrencyLimit !== '') {
      if (!Number.isInteger(Number(concurrencyLimit)) || Number(concurrencyLimit) < 0) {
        return res.status(400).json({ error: 'Concurrency limit must be a non-negative integer' });
      }
      updates.concurrencyLimit = Number(concurrencyLimit);
    }
    
    if (rateLimitWindow !== undefined && rateLimitWindow !== null && rateLimitWindow !== '') {
      if (!Number.isInteger(Number(rateLimitWindow)) || Number(rateLimitWindow) < 0) {
        return res.status(400).json({ error: 'Rate limit window must be a non-negative integer (minutes)' });
      }
      updates.rateLimitWindow = Number(rateLimitWindow);
    }
    
    if (rateLimitRequests !== undefined && rateLimitRequests !== null && rateLimitRequests !== '') {
      if (!Number.isInteger(Number(rateLimitRequests)) || Number(rateLimitRequests) < 0) {
        return res.status(400).json({ error: 'Rate limit requests must be a non-negative integer' });
      }
      updates.rateLimitRequests = Number(rateLimitRequests);
    }

    if (claudeAccountId !== undefined) {
      // 空字符串表示解绑，null或空字符串都设置为空字符串
      updates.claudeAccountId = claudeAccountId || '';
    }

    // 处理模型限制字段
    if (enableModelRestriction !== undefined) {
      if (typeof enableModelRestriction !== 'boolean') {
        return res.status(400).json({ error: 'Enable model restriction must be a boolean' });
      }
      updates.enableModelRestriction = enableModelRestriction;
    }

    if (restrictedModels !== undefined) {
      if (!Array.isArray(restrictedModels)) {
        return res.status(400).json({ error: 'Restricted models must be an array' });
      }
      updates.restrictedModels = restrictedModels;
    }

    await apiKeyService.updateApiKey(keyId, updates);
    
    logger.success(`📝 Admin updated API key: ${keyId}`);
    res.json({ success: true, message: 'API key updated successfully' });
  } catch (error) {
    logger.error('❌ Failed to update API key:', error);
    res.status(500).json({ error: 'Failed to update API key', message: error.message });
  }
});

// 删除API Key
router.delete('/api-keys/:keyId', authenticateAdmin, async (req, res) => {
  try {
    const { keyId } = req.params;
    
    await apiKeyService.deleteApiKey(keyId);
    
    logger.success(`🗑️ Admin deleted API key: ${keyId}`);
    res.json({ success: true, message: 'API key deleted successfully' });
  } catch (error) {
    logger.error('❌ Failed to delete API key:', error);
    res.status(500).json({ error: 'Failed to delete API key', message: error.message });
  }
});

// 🏢 Claude 账户管理

// 生成OAuth授权URL
router.post('/claude-accounts/generate-auth-url', authenticateAdmin, async (req, res) => {
  try {
    const { proxy } = req.body; // 接收代理配置
    
    logger.info('📋 Received OAuth URL generation request', {
      hasProxy: !!proxy,
      proxyType: proxy?.type || 'none',
      proxyHost: proxy?.host || 'none',
      proxyPort: proxy?.port || 'none',
      hasProxyAuth: !!(proxy?.username && proxy?.password)
    });
    
    const oauthParams = await oauthHelper.generateOAuthParams();
    
    // 将codeVerifier和state临时存储到Redis，用于后续验证
    const sessionId = require('crypto').randomUUID();
    const sessionData = {
      codeVerifier: oauthParams.codeVerifier,
      state: oauthParams.state,
      codeChallenge: oauthParams.codeChallenge,
      proxy: proxy || null, // 存储代理配置
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString() // 10分钟过期
    };
    
    await redis.setOAuthSession(sessionId, sessionData);
    
    logger.info('💾 OAuth session stored in Redis', {
      sessionId: sessionId,
      hasProxy: !!sessionData.proxy,
      proxyStored: sessionData.proxy ? {
        type: sessionData.proxy.type,
        host: sessionData.proxy.host,
        port: sessionData.proxy.port,
        hasAuth: !!(sessionData.proxy.username && sessionData.proxy.password)
      } : null
    });
    
    logger.success('🔗 Generated OAuth authorization URL with proxy support');
    res.json({ 
      success: true, 
      data: {
        authUrl: oauthParams.authUrl,
        sessionId: sessionId,
        instructions: [
          '1. 复制上面的链接到浏览器中打开',
          '2. 登录您的 Anthropic 账户',
          '3. 同意应用权限',
          '4. 复制浏览器地址栏中的完整 URL',
          '5. 在添加账户表单中粘贴完整的回调 URL 和授权码'
        ]
      }
    });
  } catch (error) {
    logger.error('❌ Failed to generate OAuth URL:', error);
    res.status(500).json({ error: 'Failed to generate OAuth URL', message: error.message });
  }
});

// 验证授权码并获取token
router.post('/claude-accounts/exchange-code', authenticateAdmin, async (req, res) => {
  try {
    const { sessionId, authorizationCode, callbackUrl } = req.body;
    
    if (!sessionId || (!authorizationCode && !callbackUrl)) {
      return res.status(400).json({ error: 'Session ID and authorization code (or callback URL) are required' });
    }
    
    logger.info('🔄 Starting OAuth code exchange', {
      sessionId: sessionId,
      hasAuthCode: !!authorizationCode,
      hasCallbackUrl: !!callbackUrl,
      inputLength: (callbackUrl || authorizationCode || '').length
    });
    
    // 从Redis获取OAuth会话信息
    const oauthSession = await redis.getOAuthSession(sessionId);
    if (!oauthSession) {
      logger.error('❌ OAuth session not found in Redis', { sessionId });
      return res.status(400).json({ error: 'Invalid or expired OAuth session' });
    }
    
    logger.info('📥 Retrieved OAuth session from Redis', {
      sessionId: sessionId,
      hasCodeVerifier: !!oauthSession.codeVerifier,
      hasState: !!oauthSession.state,
      hasProxy: !!oauthSession.proxy,
      proxyFromRedis: oauthSession.proxy ? {
        type: oauthSession.proxy.type,
        host: oauthSession.proxy.host,
        port: oauthSession.proxy.port,
        hasAuth: !!(oauthSession.proxy.username && oauthSession.proxy.password)
      } : null
    });
    
    // 检查会话是否过期
    if (new Date() > new Date(oauthSession.expiresAt)) {
      await redis.deleteOAuthSession(sessionId);
      return res.status(400).json({ error: 'OAuth session has expired, please generate a new authorization URL' });
    }
    
    // 统一处理授权码输入（可能是直接的code或完整的回调URL）
    let finalAuthCode;
    const inputValue = callbackUrl || authorizationCode;
    
    try {
      finalAuthCode = oauthHelper.parseCallbackUrl(inputValue);
      logger.info('✅ Successfully parsed authorization code', {
        codeLength: finalAuthCode.length,
        codePrefix: finalAuthCode.substring(0, 10) + '...'
      });
    } catch (parseError) {
      logger.error('❌ Failed to parse authorization input', {
        error: parseError.message,
        inputLength: inputValue.length,
        inputPrefix: inputValue.substring(0, 50) + '...'
      });
      return res.status(400).json({ error: 'Failed to parse authorization input', message: parseError.message });
    }
    
    // 交换访问令牌
    logger.info('🔄 About to exchange code for tokens with proxy config:', {
      hasProxy: !!oauthSession.proxy,
      proxyConfig: oauthSession.proxy
    });
    
    const tokenData = await oauthHelper.exchangeCodeForTokens(
      finalAuthCode,
      oauthSession.codeVerifier,
      oauthSession.state,
      oauthSession.proxy // 传递代理配置
    );
    
    // 清理OAuth会话
    await redis.deleteOAuthSession(sessionId);
    
    logger.success('🎉 Successfully exchanged authorization code for tokens');
    res.json({ 
      success: true, 
      data: {
        claudeAiOauth: tokenData
      }
    });
  } catch (error) {
    logger.error('❌ Failed to exchange authorization code:', {
      error: error.message,
      sessionId: req.body.sessionId,
      codeLength: (req.body.callbackUrl || req.body.authorizationCode || '').length,
      codePrefix: ((req.body.callbackUrl || req.body.authorizationCode || '').substring(0, 10) + '...')
    });
    res.status(500).json({ error: 'Failed to exchange authorization code', message: error.message });
  }
});

// 获取所有Claude账户
router.get('/claude-accounts', authenticateAdmin, async (req, res) => {
  try {
    const accounts = await claudeAccountService.getAllAccounts();
    res.json({ success: true, data: accounts });
  } catch (error) {
    logger.error('❌ Failed to get Claude accounts:', error);
    res.status(500).json({ error: 'Failed to get Claude accounts', message: error.message });
  }
});

// 创建新的Claude账户
router.post('/claude-accounts', authenticateAdmin, async (req, res) => {
  try {
    const {
      name,
      description,
      email,
      password,
      refreshToken,
      claudeAiOauth,
      proxy,
      accountType
    } = req.body;

    if (!name) {
      return res.status(400).json({ error: 'Name is required' });
    }

    // 验证accountType的有效性
    if (accountType && !['shared', 'dedicated'].includes(accountType)) {
      return res.status(400).json({ error: 'Invalid account type. Must be "shared" or "dedicated"' });
    }

    const newAccount = await claudeAccountService.createAccount({
      name,
      description,
      email,
      password,
      refreshToken,
      claudeAiOauth,
      proxy,
      accountType: accountType || 'shared' // 默认为共享类型
    });

    logger.success(`🏢 Admin created new Claude account: ${name} (${accountType || 'shared'})`);
    res.json({ success: true, data: newAccount });
  } catch (error) {
    logger.error('❌ Failed to create Claude account:', error);
    res.status(500).json({ error: 'Failed to create Claude account', message: error.message });
  }
});

// 刷新Claude账户token (具体路由要放在通用路由前面)
router.post('/claude-accounts/:accountId/refresh', authenticateAdmin, async (req, res) => {
  try {
    const { accountId } = req.params;
    
    const result = await claudeAccountService.refreshAccountToken(accountId);
    
    logger.success(`🔄 Admin refreshed token for Claude account: ${accountId}`);
    res.json({ success: true, data: result });
  } catch (error) {
    logger.error('❌ Failed to refresh Claude account token:', error);
    res.status(500).json({ error: 'Failed to refresh token', message: error.message });
  }
});

// 切换Claude账户状态（启用/禁用）(具体路由要放在通用路由前面)
router.post('/claude-accounts/:accountId/toggle-status', authenticateAdmin, async (req, res) => {
  try {
    const { accountId } = req.params;
    
    const result = await claudeAccountService.toggleAccountStatus(accountId);
    
    logger.success(`🔄 Admin toggled status for Claude account: ${accountId}`);
    res.json({ success: true, data: result });
  } catch (error) {
    logger.error('❌ Failed to toggle Claude account status:', error);
    res.status(500).json({ error: 'Failed to toggle account status', message: error.message });
  }
});

// 更新Claude账户
router.put('/claude-accounts/:accountId', authenticateAdmin, async (req, res) => {
  try {
    const { accountId } = req.params;
    const updates = req.body;

    await claudeAccountService.updateAccount(accountId, updates);
    
    logger.success(`📝 Admin updated Claude account: ${accountId}`);
    res.json({ success: true, message: 'Claude account updated successfully' });
  } catch (error) {
    logger.error('❌ Failed to update Claude account:', error);
    res.status(500).json({ error: 'Failed to update Claude account', message: error.message });
  }
});

// 删除Claude账户
router.delete('/claude-accounts/:accountId', authenticateAdmin, async (req, res) => {
  try {
    const { accountId } = req.params;
    
    await claudeAccountService.deleteAccount(accountId);
    
    logger.success(`🗑️ Admin deleted Claude account: ${accountId}`);
    res.json({ success: true, message: 'Claude account deleted successfully' });
  } catch (error) {
    logger.error('❌ Failed to delete Claude account:', error);
    res.status(500).json({ error: 'Failed to delete Claude account', message: error.message });
  }
});

// 📊 系统统计

// 获取系统概览
router.get('/dashboard', authenticateAdmin, async (req, res) => {
  try {
    const [, apiKeys, accounts, todayStats, systemAverages] = await Promise.all([
      redis.getSystemStats(),
      apiKeyService.getAllApiKeys(),
      claudeAccountService.getAllAccounts(),
      redis.getTodayStats(),
      redis.getSystemAverages()
    ]);

    // 计算使用统计（包含cache tokens）
    const totalTokensUsed = apiKeys.reduce((sum, key) => sum + (key.usage?.total?.tokens || 0), 0);
    const totalRequestsUsed = apiKeys.reduce((sum, key) => sum + (key.usage?.total?.requests || 0), 0);
    const totalInputTokensUsed = apiKeys.reduce((sum, key) => sum + (key.usage?.total?.inputTokens || 0), 0);
    const totalOutputTokensUsed = apiKeys.reduce((sum, key) => sum + (key.usage?.total?.outputTokens || 0), 0);
    const totalCacheCreateTokensUsed = apiKeys.reduce((sum, key) => sum + (key.usage?.total?.cacheCreateTokens || 0), 0);
    const totalCacheReadTokensUsed = apiKeys.reduce((sum, key) => sum + (key.usage?.total?.cacheReadTokens || 0), 0);
    const totalAllTokensUsed = apiKeys.reduce((sum, key) => sum + (key.usage?.total?.allTokens || 0), 0);
    
    const activeApiKeys = apiKeys.filter(key => key.isActive).length;
    const activeAccounts = accounts.filter(acc => acc.isActive && acc.status === 'active').length;
    const rateLimitedAccounts = accounts.filter(acc => acc.rateLimitStatus && acc.rateLimitStatus.isRateLimited).length;

    const dashboard = {
      overview: {
        totalApiKeys: apiKeys.length,
        activeApiKeys,
        totalClaudeAccounts: accounts.length,
        activeClaudeAccounts: activeAccounts,
        rateLimitedClaudeAccounts: rateLimitedAccounts,
        totalTokensUsed,
        totalRequestsUsed,
        totalInputTokensUsed,
        totalOutputTokensUsed,
        totalCacheCreateTokensUsed,
        totalCacheReadTokensUsed,
        totalAllTokensUsed
      },
      recentActivity: {
        apiKeysCreatedToday: todayStats.apiKeysCreatedToday,
        requestsToday: todayStats.requestsToday,
        tokensToday: todayStats.tokensToday,
        inputTokensToday: todayStats.inputTokensToday,
        outputTokensToday: todayStats.outputTokensToday,
        cacheCreateTokensToday: todayStats.cacheCreateTokensToday || 0,
        cacheReadTokensToday: todayStats.cacheReadTokensToday || 0
      },
      systemAverages: {
        rpm: systemAverages.systemRPM,
        tpm: systemAverages.systemTPM
      },
      systemHealth: {
        redisConnected: redis.isConnected,
        claudeAccountsHealthy: activeAccounts > 0,
        uptime: process.uptime()
      }
    };

    res.json({ success: true, data: dashboard });
  } catch (error) {
    logger.error('❌ Failed to get dashboard data:', error);
    res.status(500).json({ error: 'Failed to get dashboard data', message: error.message });
  }
});

// 获取使用统计
router.get('/usage-stats', authenticateAdmin, async (req, res) => {
  try {
    const { period = 'daily' } = req.query; // daily, monthly
    
    // 获取基础API Key统计
    const apiKeys = await apiKeyService.getAllApiKeys();
    
    const stats = apiKeys.map(key => ({
      keyId: key.id,
      keyName: key.name,
      usage: key.usage
    }));

    res.json({ success: true, data: { period, stats } });
  } catch (error) {
    logger.error('❌ Failed to get usage stats:', error);
    res.status(500).json({ error: 'Failed to get usage stats', message: error.message });
  }
});

// 获取按模型的使用统计和费用
router.get('/model-stats', authenticateAdmin, async (req, res) => {
  try {
    const { period = 'daily' } = req.query; // daily, monthly
    const today = new Date().toISOString().split('T')[0];
    const currentMonth = `${new Date().getFullYear()}-${String(new Date().getMonth() + 1).padStart(2, '0')}`;
    
    logger.info(`📊 Getting global model stats, period: ${period}, today: ${today}, currentMonth: ${currentMonth}`);
    
    const client = redis.getClientSafe();
    
    // 获取所有模型的统计数据
    const pattern = period === 'daily' ? `usage:model:daily:*:${today}` : `usage:model:monthly:*:${currentMonth}`;
    logger.info(`📊 Searching pattern: ${pattern}`);
    
    const keys = await client.keys(pattern);
    logger.info(`📊 Found ${keys.length} matching keys:`, keys);
    
    const modelStats = [];
    
    for (const key of keys) {
      const match = key.match(period === 'daily' ? 
        /usage:model:daily:(.+):\d{4}-\d{2}-\d{2}$/ : 
        /usage:model:monthly:(.+):\d{4}-\d{2}$/
      );
      
      if (!match) {
        logger.warn(`📊 Pattern mismatch for key: ${key}`);
        continue;
      }
      
      const model = match[1];
      const data = await client.hgetall(key);
      
      logger.info(`📊 Model ${model} data:`, data);
      
      if (data && Object.keys(data).length > 0) {
        const usage = {
          input_tokens: parseInt(data.inputTokens) || 0,
          output_tokens: parseInt(data.outputTokens) || 0,
          cache_creation_input_tokens: parseInt(data.cacheCreateTokens) || 0,
          cache_read_input_tokens: parseInt(data.cacheReadTokens) || 0
        };
        
        // 计算费用
        const costData = CostCalculator.calculateCost(usage, model);
        
        modelStats.push({
          model,
          period,
          requests: parseInt(data.requests) || 0,
          inputTokens: usage.input_tokens,
          outputTokens: usage.output_tokens,
          cacheCreateTokens: usage.cache_creation_input_tokens,
          cacheReadTokens: usage.cache_read_input_tokens,
          allTokens: parseInt(data.allTokens) || 0,
          usage: {
            requests: parseInt(data.requests) || 0,
            inputTokens: usage.input_tokens,
            outputTokens: usage.output_tokens,
            cacheCreateTokens: usage.cache_creation_input_tokens,
            cacheReadTokens: usage.cache_read_input_tokens,
            totalTokens: usage.input_tokens + usage.output_tokens + usage.cache_creation_input_tokens + usage.cache_read_input_tokens
          },
          costs: costData.costs,
          formatted: costData.formatted,
          pricing: costData.pricing
        });
      }
    }
    
    // 按总费用排序
    modelStats.sort((a, b) => b.costs.total - a.costs.total);
    
    logger.info(`📊 Returning ${modelStats.length} global model stats for period ${period}:`, modelStats);
    
    res.json({ success: true, data: modelStats });
  } catch (error) {
    logger.error('❌ Failed to get model stats:', error);
    res.status(500).json({ error: 'Failed to get model stats', message: error.message });
  }
});

// 🔧 系统管理

// 清理过期数据
router.post('/cleanup', authenticateAdmin, async (req, res) => {
  try {
    const [expiredKeys, errorAccounts] = await Promise.all([
      apiKeyService.cleanupExpiredKeys(),
      claudeAccountService.cleanupErrorAccounts()
    ]);
    
    await redis.cleanup();
    
    logger.success(`🧹 Admin triggered cleanup: ${expiredKeys} expired keys, ${errorAccounts} error accounts`);
    
    res.json({
      success: true,
      message: 'Cleanup completed',
      data: {
        expiredKeysRemoved: expiredKeys,
        errorAccountsReset: errorAccounts
      }
    });
  } catch (error) {
    logger.error('❌ Cleanup failed:', error);
    res.status(500).json({ error: 'Cleanup failed', message: error.message });
  }
});

// 获取使用趋势数据
router.get('/usage-trend', authenticateAdmin, async (req, res) => {
  try {
    const { days = 7, granularity = 'day', startDate, endDate } = req.query;
    const client = redis.getClientSafe();
    
    const trendData = [];
    
    if (granularity === 'hour') {
      // 小时粒度统计
      let startTime, endTime;
      
      if (startDate && endDate) {
        // 使用自定义时间范围
        startTime = new Date(startDate);
        endTime = new Date(endDate);
      } else {
        // 默认最近24小时
        endTime = new Date();
        startTime = new Date(endTime.getTime() - 24 * 60 * 60 * 1000);
      }
      
      // 确保时间范围不超过24小时
      const timeDiff = endTime - startTime;
      if (timeDiff > 24 * 60 * 60 * 1000) {
        return res.status(400).json({ 
          error: '小时粒度查询时间范围不能超过24小时' 
        });
      }
      
      // 按小时遍历
      const currentHour = new Date(startTime);
      currentHour.setMinutes(0, 0, 0);
      
      while (currentHour <= endTime) {
        const dateStr = currentHour.toISOString().split('T')[0];
        const hour = String(currentHour.getHours()).padStart(2, '0');
        const hourKey = `${dateStr}:${hour}`;
        
        // 获取当前小时的模型统计数据
        const modelPattern = `usage:model:hourly:*:${hourKey}`;
        const modelKeys = await client.keys(modelPattern);
        
        let hourInputTokens = 0;
        let hourOutputTokens = 0;
        let hourRequests = 0;
        let hourCacheCreateTokens = 0;
        let hourCacheReadTokens = 0;
        let hourCost = 0;
        
        for (const modelKey of modelKeys) {
          const modelMatch = modelKey.match(/usage:model:hourly:(.+):\d{4}-\d{2}-\d{2}:\d{2}$/);
          if (!modelMatch) continue;
          
          const model = modelMatch[1];
          const data = await client.hgetall(modelKey);
          
          if (data && Object.keys(data).length > 0) {
            const modelInputTokens = parseInt(data.inputTokens) || 0;
            const modelOutputTokens = parseInt(data.outputTokens) || 0;
            const modelCacheCreateTokens = parseInt(data.cacheCreateTokens) || 0;
            const modelCacheReadTokens = parseInt(data.cacheReadTokens) || 0;
            const modelRequests = parseInt(data.requests) || 0;
            
            hourInputTokens += modelInputTokens;
            hourOutputTokens += modelOutputTokens;
            hourCacheCreateTokens += modelCacheCreateTokens;
            hourCacheReadTokens += modelCacheReadTokens;
            hourRequests += modelRequests;
            
            const modelUsage = {
              input_tokens: modelInputTokens,
              output_tokens: modelOutputTokens,
              cache_creation_input_tokens: modelCacheCreateTokens,
              cache_read_input_tokens: modelCacheReadTokens
            };
            const modelCostResult = CostCalculator.calculateCost(modelUsage, model);
            hourCost += modelCostResult.costs.total;
          }
        }
        
        // 如果没有模型级别的数据，尝试API Key级别的数据
        if (modelKeys.length === 0) {
          const pattern = `usage:hourly:*:${hourKey}`;
          const keys = await client.keys(pattern);
          
          for (const key of keys) {
            const data = await client.hgetall(key);
            if (data) {
              hourInputTokens += parseInt(data.inputTokens) || 0;
              hourOutputTokens += parseInt(data.outputTokens) || 0;
              hourRequests += parseInt(data.requests) || 0;
              hourCacheCreateTokens += parseInt(data.cacheCreateTokens) || 0;
              hourCacheReadTokens += parseInt(data.cacheReadTokens) || 0;
            }
          }
          
          const usage = {
            input_tokens: hourInputTokens,
            output_tokens: hourOutputTokens,
            cache_creation_input_tokens: hourCacheCreateTokens,
            cache_read_input_tokens: hourCacheReadTokens
          };
          const costResult = CostCalculator.calculateCost(usage, 'unknown');
          hourCost = costResult.costs.total;
        }
        
        trendData.push({
          date: hourKey,
          hour: currentHour.toISOString(),
          inputTokens: hourInputTokens,
          outputTokens: hourOutputTokens,
          requests: hourRequests,
          cacheCreateTokens: hourCacheCreateTokens,
          cacheReadTokens: hourCacheReadTokens,
          totalTokens: hourInputTokens + hourOutputTokens + hourCacheCreateTokens + hourCacheReadTokens,
          cost: hourCost
        });
        
        // 移到下一个小时
        currentHour.setHours(currentHour.getHours() + 1);
      }
      
    } else {
      // 天粒度统计（保持原有逻辑）
      const daysCount = parseInt(days) || 7;
      const today = new Date();
      
      // 获取过去N天的数据
      for (let i = 0; i < daysCount; i++) {
        const date = new Date(today);
        date.setDate(date.getDate() - i);
        const dateStr = date.toISOString().split('T')[0];
        
        // 汇总当天所有API Key的使用数据
        const pattern = `usage:daily:*:${dateStr}`;
        const keys = await client.keys(pattern);
      
      let dayInputTokens = 0;
      let dayOutputTokens = 0;
      let dayRequests = 0;
      let dayCacheCreateTokens = 0;
      let dayCacheReadTokens = 0;
      let dayCost = 0;
      
      // 按模型统计使用量
      // const modelUsageMap = new Map();
      
      // 获取当天所有模型的使用数据
      const modelPattern = `usage:model:daily:*:${dateStr}`;
      const modelKeys = await client.keys(modelPattern);
      
      for (const modelKey of modelKeys) {
        // 解析模型名称
        const modelMatch = modelKey.match(/usage:model:daily:(.+):\d{4}-\d{2}-\d{2}$/);
        if (!modelMatch) continue;
        
        const model = modelMatch[1];
        const data = await client.hgetall(modelKey);
        
        if (data && Object.keys(data).length > 0) {
          const modelInputTokens = parseInt(data.inputTokens) || 0;
          const modelOutputTokens = parseInt(data.outputTokens) || 0;
          const modelCacheCreateTokens = parseInt(data.cacheCreateTokens) || 0;
          const modelCacheReadTokens = parseInt(data.cacheReadTokens) || 0;
          const modelRequests = parseInt(data.requests) || 0;
          
          // 累加总数
          dayInputTokens += modelInputTokens;
          dayOutputTokens += modelOutputTokens;
          dayCacheCreateTokens += modelCacheCreateTokens;
          dayCacheReadTokens += modelCacheReadTokens;
          dayRequests += modelRequests;
          
          // 按模型计算费用
          const modelUsage = {
            input_tokens: modelInputTokens,
            output_tokens: modelOutputTokens,
            cache_creation_input_tokens: modelCacheCreateTokens,
            cache_read_input_tokens: modelCacheReadTokens
          };
          const modelCostResult = CostCalculator.calculateCost(modelUsage, model);
          dayCost += modelCostResult.costs.total;
        }
      }
      
      // 如果没有模型级别的数据，回退到原始方法
      if (modelKeys.length === 0 && keys.length > 0) {
        for (const key of keys) {
          const data = await client.hgetall(key);
          if (data) {
            dayInputTokens += parseInt(data.inputTokens) || 0;
            dayOutputTokens += parseInt(data.outputTokens) || 0;
            dayRequests += parseInt(data.requests) || 0;
            dayCacheCreateTokens += parseInt(data.cacheCreateTokens) || 0;
            dayCacheReadTokens += parseInt(data.cacheReadTokens) || 0;
          }
        }
        
        // 使用默认模型价格计算
        const usage = {
          input_tokens: dayInputTokens,
          output_tokens: dayOutputTokens,
          cache_creation_input_tokens: dayCacheCreateTokens,
          cache_read_input_tokens: dayCacheReadTokens
        };
        const costResult = CostCalculator.calculateCost(usage, 'unknown');
        dayCost = costResult.costs.total;
      }
      
      trendData.push({
        date: dateStr,
        inputTokens: dayInputTokens,
        outputTokens: dayOutputTokens,
        requests: dayRequests,
        cacheCreateTokens: dayCacheCreateTokens,
        cacheReadTokens: dayCacheReadTokens,
        totalTokens: dayInputTokens + dayOutputTokens + dayCacheCreateTokens + dayCacheReadTokens,
        cost: dayCost,
        formattedCost: CostCalculator.formatCost(dayCost)
      });
    }
    
    }
    
    // 按日期正序排列
    if (granularity === 'hour') {
      trendData.sort((a, b) => new Date(a.hour) - new Date(b.hour));
    } else {
      trendData.sort((a, b) => new Date(a.date) - new Date(b.date));
    }
    
    res.json({ success: true, data: trendData, granularity });
  } catch (error) {
    logger.error('❌ Failed to get usage trend:', error);
    res.status(500).json({ error: 'Failed to get usage trend', message: error.message });
  }
});

// 获取单个API Key的模型统计
router.get('/api-keys/:keyId/model-stats', authenticateAdmin, async (req, res) => {
  try {
    const { keyId } = req.params;
    const { period = 'monthly', startDate, endDate } = req.query;
    
    logger.info(`📊 Getting model stats for API key: ${keyId}, period: ${period}, startDate: ${startDate}, endDate: ${endDate}`);
    
    const client = redis.getClientSafe();
    const today = new Date().toISOString().split('T')[0];
    const currentMonth = `${new Date().getFullYear()}-${String(new Date().getMonth() + 1).padStart(2, '0')}`;
    
    let searchPatterns = [];
    
    if (period === 'custom' && startDate && endDate) {
      // 自定义日期范围，生成多个日期的搜索模式
      const start = new Date(startDate);
      const end = new Date(endDate);
      
      // 确保日期范围有效
      if (start > end) {
        return res.status(400).json({ error: 'Start date must be before or equal to end date' });
      }
      
      // 限制最大范围为31天
      const daysDiff = Math.ceil((end - start) / (1000 * 60 * 60 * 24)) + 1;
      if (daysDiff > 31) {
        return res.status(400).json({ error: 'Date range cannot exceed 31 days' });
      }
      
      // 生成日期范围内所有日期的搜索模式
      for (let d = new Date(start); d <= end; d.setDate(d.getDate() + 1)) {
        const dateStr = d.toISOString().split('T')[0];
        searchPatterns.push(`usage:${keyId}:model:daily:*:${dateStr}`);
      }
      
      logger.info(`📊 Custom date range patterns: ${searchPatterns.length} days from ${startDate} to ${endDate}`);
    } else {
      // 原有的预设期间逻辑
      const pattern = period === 'daily' ? 
        `usage:${keyId}:model:daily:*:${today}` : 
        `usage:${keyId}:model:monthly:*:${currentMonth}`;
      searchPatterns = [pattern];
      logger.info(`📊 Preset period pattern: ${pattern}`);
    }
    
    // 汇总所有匹配的数据
    const modelStatsMap = new Map();
    const modelStats = []; // 定义结果数组
    
    for (const pattern of searchPatterns) {
      const keys = await client.keys(pattern);
      logger.info(`📊 Pattern ${pattern} found ${keys.length} keys`);
      
      for (const key of keys) {
        const match = key.match(/usage:.+:model:daily:(.+):\d{4}-\d{2}-\d{2}$/) || 
                     key.match(/usage:.+:model:monthly:(.+):\d{4}-\d{2}$/);
        
        if (!match) {
          logger.warn(`📊 Pattern mismatch for key: ${key}`);
          continue;
        }
        
        const model = match[1];
        const data = await client.hgetall(key);
        
        if (data && Object.keys(data).length > 0) {
          // 累加同一模型的数据
          if (!modelStatsMap.has(model)) {
            modelStatsMap.set(model, {
              requests: 0,
              inputTokens: 0,
              outputTokens: 0,
              cacheCreateTokens: 0,
              cacheReadTokens: 0,
              allTokens: 0
            });
          }
          
          const stats = modelStatsMap.get(model);
          stats.requests += parseInt(data.requests) || 0;
          stats.inputTokens += parseInt(data.inputTokens) || 0;
          stats.outputTokens += parseInt(data.outputTokens) || 0;
          stats.cacheCreateTokens += parseInt(data.cacheCreateTokens) || 0;
          stats.cacheReadTokens += parseInt(data.cacheReadTokens) || 0;
          stats.allTokens += parseInt(data.allTokens) || 0;
        }
      }
    }
    
    // 将汇总的数据转换为最终结果
    for (const [model, stats] of modelStatsMap) {
      logger.info(`📊 Model ${model} aggregated data:`, stats);
      
      const usage = {
        input_tokens: stats.inputTokens,
        output_tokens: stats.outputTokens,
        cache_creation_input_tokens: stats.cacheCreateTokens,
        cache_read_input_tokens: stats.cacheReadTokens
      };
      
      // 使用CostCalculator计算费用
      const costData = CostCalculator.calculateCost(usage, model);
      
      modelStats.push({
        model,
        requests: stats.requests,
        inputTokens: stats.inputTokens,
        outputTokens: stats.outputTokens,
        cacheCreateTokens: stats.cacheCreateTokens,
        cacheReadTokens: stats.cacheReadTokens,
        allTokens: stats.allTokens,
        // 添加费用信息
        costs: costData.costs,
        formatted: costData.formatted,
        pricing: costData.pricing,
        usingDynamicPricing: costData.usingDynamicPricing
      });
    }
    
    // 如果没有找到模型级别的详细数据，尝试从汇总数据中生成展示
    if (modelStats.length === 0) {
      logger.info(`📊 No detailed model stats found, trying to get aggregate data for API key ${keyId}`);
      
      // 尝试从API Keys列表中获取usage数据作为备选方案
      try {
        const apiKeys = await apiKeyService.getAllApiKeys();
        const targetApiKey = apiKeys.find(key => key.id === keyId);
        
        if (targetApiKey && targetApiKey.usage) {
          logger.info(`📊 Found API key usage data from getAllApiKeys for ${keyId}:`, targetApiKey.usage);
          
          // 从汇总数据创建展示条目
          let usageData;
          if (period === 'custom' || period === 'daily') {
            // 对于自定义或日统计，使用daily数据或total数据
            usageData = targetApiKey.usage.daily || targetApiKey.usage.total;
          } else {
            // 对于月统计，使用monthly数据或total数据
            usageData = targetApiKey.usage.monthly || targetApiKey.usage.total;
          }
          
          if (usageData && usageData.allTokens > 0) {
            const usage = {
              input_tokens: usageData.inputTokens || 0,
              output_tokens: usageData.outputTokens || 0,
              cache_creation_input_tokens: usageData.cacheCreateTokens || 0,
              cache_read_input_tokens: usageData.cacheReadTokens || 0
            };
            
            // 对于汇总数据，使用默认模型计算费用
            const costData = CostCalculator.calculateCost(usage, 'claude-3-5-sonnet-20241022');
            
            modelStats.push({
              model: '总体使用 (历史数据)',
              requests: usageData.requests || 0,
              inputTokens: usageData.inputTokens || 0,
              outputTokens: usageData.outputTokens || 0,
              cacheCreateTokens: usageData.cacheCreateTokens || 0,
              cacheReadTokens: usageData.cacheReadTokens || 0,
              allTokens: usageData.allTokens || 0,
              // 添加费用信息
              costs: costData.costs,
              formatted: costData.formatted,
              pricing: costData.pricing,
              usingDynamicPricing: costData.usingDynamicPricing
            });
            
            logger.info('📊 Generated display data from API key usage stats');
          } else {
            logger.info(`📊 No usage data found for period ${period} in API key data`);
          }
        } else {
          logger.info(`📊 API key ${keyId} not found or has no usage data`);
        }
      } catch (error) {
        logger.error('❌ Error fetching API key usage data:', error);
      }
    }
    
    // 按总token数降序排列
    modelStats.sort((a, b) => b.allTokens - a.allTokens);
    
    logger.info(`📊 Returning ${modelStats.length} model stats for API key ${keyId}:`, modelStats);
    
    res.json({ success: true, data: modelStats });
  } catch (error) {
    logger.error('❌ Failed to get API key model stats:', error);
    res.status(500).json({ error: 'Failed to get API key model stats', message: error.message });
  }
});


// 获取按API Key分组的使用趋势
router.get('/api-keys-usage-trend', authenticateAdmin, async (req, res) => {
  try {
    const { granularity = 'day', days = 7, startDate, endDate } = req.query;
    
    logger.info(`📊 Getting API keys usage trend, granularity: ${granularity}, days: ${days}`);
    
    const client = redis.getClientSafe();
    const trendData = [];
    
    // 获取所有API Keys
    const apiKeys = await apiKeyService.getAllApiKeys();
    const apiKeyMap = new Map(apiKeys.map(key => [key.id, key]));
    
    if (granularity === 'hour') {
      // 小时粒度统计
      let endTime, startTime;
      
      if (startDate && endDate) {
        // 自定义时间范围
        startTime = new Date(startDate);
        endTime = new Date(endDate);
      } else {
        // 默认近24小时
        endTime = new Date();
        startTime = new Date(endTime.getTime() - 24 * 60 * 60 * 1000);
      }
      
      // 按小时遍历
      const currentHour = new Date(startTime);
      currentHour.setMinutes(0, 0, 0);
      
      while (currentHour <= endTime) {
        const hourKey = currentHour.toISOString().split(':')[0].replace('T', ':');
        
        // 获取这个小时所有API Key的数据
        const pattern = `usage:hourly:*:${hourKey}`;
        const keys = await client.keys(pattern);
        
        const hourData = {
          hour: currentHour.toISOString(),
          apiKeys: {}
        };
        
        for (const key of keys) {
          const match = key.match(/usage:hourly:(.+?):\d{4}-\d{2}-\d{2}:\d{2}/);
          if (!match) continue;
          
          const apiKeyId = match[1];
          const data = await client.hgetall(key);
          
          if (data && apiKeyMap.has(apiKeyId)) {
            const totalTokens = (parseInt(data.inputTokens) || 0) + 
                              (parseInt(data.outputTokens) || 0) + 
                              (parseInt(data.cacheCreateTokens) || 0) + 
                              (parseInt(data.cacheReadTokens) || 0);
            
            hourData.apiKeys[apiKeyId] = {
              name: apiKeyMap.get(apiKeyId).name,
              tokens: totalTokens
            };
          }
        }
        
        trendData.push(hourData);
        currentHour.setHours(currentHour.getHours() + 1);
      }
      
    } else {
      // 天粒度统计
      const daysCount = parseInt(days) || 7;
      const today = new Date();
      
      // 获取过去N天的数据
      for (let i = 0; i < daysCount; i++) {
        const date = new Date(today);
        date.setDate(date.getDate() - i);
        const dateStr = date.toISOString().split('T')[0];
        
        // 获取这一天所有API Key的数据
        const pattern = `usage:daily:*:${dateStr}`;
        const keys = await client.keys(pattern);
        
        const dayData = {
          date: dateStr,
          apiKeys: {}
        };
        
        for (const key of keys) {
          const match = key.match(/usage:daily:(.+?):\d{4}-\d{2}-\d{2}/);
          if (!match) continue;
          
          const apiKeyId = match[1];
          const data = await client.hgetall(key);
          
          if (data && apiKeyMap.has(apiKeyId)) {
            const totalTokens = (parseInt(data.inputTokens) || 0) + 
                              (parseInt(data.outputTokens) || 0) + 
                              (parseInt(data.cacheCreateTokens) || 0) + 
                              (parseInt(data.cacheReadTokens) || 0);
            
            dayData.apiKeys[apiKeyId] = {
              name: apiKeyMap.get(apiKeyId).name,
              tokens: totalTokens
            };
          }
        }
        
        trendData.push(dayData);
      }
    }
    
    // 按时间正序排列
    if (granularity === 'hour') {
      trendData.sort((a, b) => new Date(a.hour) - new Date(b.hour));
    } else {
      trendData.sort((a, b) => new Date(a.date) - new Date(b.date));
    }
    
    // 计算每个API Key的总token数，用于排序
    const apiKeyTotals = new Map();
    for (const point of trendData) {
      for (const [apiKeyId, data] of Object.entries(point.apiKeys)) {
        apiKeyTotals.set(apiKeyId, (apiKeyTotals.get(apiKeyId) || 0) + data.tokens);
      }
    }
    
    // 获取前10个使用量最多的API Key
    const topApiKeys = Array.from(apiKeyTotals.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([apiKeyId]) => apiKeyId);
    
    res.json({ 
      success: true, 
      data: trendData, 
      granularity,
      topApiKeys,
      totalApiKeys: apiKeyTotals.size
    });
  } catch (error) {
    logger.error('❌ Failed to get API keys usage trend:', error);
    res.status(500).json({ error: 'Failed to get API keys usage trend', message: error.message });
  }
});

// 计算总体使用费用
router.get('/usage-costs', authenticateAdmin, async (req, res) => {
  try {
    const { period = 'all' } = req.query; // all, today, monthly
    
    logger.info(`💰 Calculating usage costs for period: ${period}`);
    
    // 获取所有API Keys的使用统计
    const apiKeys = await apiKeyService.getAllApiKeys();
    
    let totalCosts = {
      inputCost: 0,
      outputCost: 0,
      cacheCreateCost: 0,
      cacheReadCost: 0,
      totalCost: 0
    };
    
    let modelCosts = {};
    
    // 按模型统计费用
    const client = redis.getClientSafe();
    const today = new Date().toISOString().split('T')[0];
    const currentMonth = `${new Date().getFullYear()}-${String(new Date().getMonth() + 1).padStart(2, '0')}`;
    
    let pattern;
    if (period === 'today') {
      pattern = `usage:model:daily:*:${today}`;
    } else if (period === 'monthly') {
      pattern = `usage:model:monthly:*:${currentMonth}`;
    } else {
      // 全部时间，先尝试从Redis获取所有历史模型统计数据（只使用monthly数据避免重复计算）
      const allModelKeys = await client.keys('usage:model:monthly:*:*');
      logger.info(`💰 Total period calculation: found ${allModelKeys.length} monthly model keys`);
      
      if (allModelKeys.length > 0) {
        // 如果有详细的模型统计数据，使用模型级别的计算
        const modelUsageMap = new Map();
        
        for (const key of allModelKeys) {
          // 解析模型名称（只处理monthly数据）
          let modelMatch = key.match(/usage:model:monthly:(.+):(\d{4}-\d{2})$/);
          if (!modelMatch) continue;
          
          const model = modelMatch[1];
          const data = await client.hgetall(key);
          
          if (data && Object.keys(data).length > 0) {
            if (!modelUsageMap.has(model)) {
              modelUsageMap.set(model, {
                inputTokens: 0,
                outputTokens: 0,
                cacheCreateTokens: 0,
                cacheReadTokens: 0
              });
            }
            
            const modelUsage = modelUsageMap.get(model);
            modelUsage.inputTokens += parseInt(data.inputTokens) || 0;
            modelUsage.outputTokens += parseInt(data.outputTokens) || 0;
            modelUsage.cacheCreateTokens += parseInt(data.cacheCreateTokens) || 0;
            modelUsage.cacheReadTokens += parseInt(data.cacheReadTokens) || 0;
          }
        }
        
        // 使用模型级别的数据计算费用
        logger.info(`💰 Processing ${modelUsageMap.size} unique models for total cost calculation`);
        
        for (const [model, usage] of modelUsageMap) {
          const usageData = {
            input_tokens: usage.inputTokens,
            output_tokens: usage.outputTokens,
            cache_creation_input_tokens: usage.cacheCreateTokens,
            cache_read_input_tokens: usage.cacheReadTokens
          };
          
          const costResult = CostCalculator.calculateCost(usageData, model);
          totalCosts.inputCost += costResult.costs.input;
          totalCosts.outputCost += costResult.costs.output;
          totalCosts.cacheCreateCost += costResult.costs.cacheWrite;
          totalCosts.cacheReadCost += costResult.costs.cacheRead;
          totalCosts.totalCost += costResult.costs.total;
          
          logger.info(`💰 Model ${model}: ${usage.inputTokens + usage.outputTokens + usage.cacheCreateTokens + usage.cacheReadTokens} tokens, cost: ${costResult.formatted.total}`);
          
          // 记录模型费用
          modelCosts[model] = {
            model,
            requests: 0, // 历史汇总数据没有请求数
            usage: usageData,
            costs: costResult.costs,
            formatted: costResult.formatted,
            usingDynamicPricing: costResult.usingDynamicPricing
          };
        }
      } else {
        // 如果没有详细的模型统计数据，回退到API Key汇总数据
        logger.warn('No detailed model statistics found, falling back to API Key aggregated data');
        
        for (const apiKey of apiKeys) {
          if (apiKey.usage && apiKey.usage.total) {
            const usage = {
              input_tokens: apiKey.usage.total.inputTokens || 0,
              output_tokens: apiKey.usage.total.outputTokens || 0,
              cache_creation_input_tokens: apiKey.usage.total.cacheCreateTokens || 0,
              cache_read_input_tokens: apiKey.usage.total.cacheReadTokens || 0
            };
            
            // 使用加权平均价格计算（基于当前活跃模型的价格分布）
            const costResult = CostCalculator.calculateCost(usage, 'claude-3-5-haiku-20241022');
            totalCosts.inputCost += costResult.costs.input;
            totalCosts.outputCost += costResult.costs.output;
            totalCosts.cacheCreateCost += costResult.costs.cacheWrite;
            totalCosts.cacheReadCost += costResult.costs.cacheRead;
            totalCosts.totalCost += costResult.costs.total;
          }
        }
      }
      
      res.json({
        success: true,
        data: {
          period,
          totalCosts: {
            ...totalCosts,
            formatted: {
              inputCost: CostCalculator.formatCost(totalCosts.inputCost),
              outputCost: CostCalculator.formatCost(totalCosts.outputCost),
              cacheCreateCost: CostCalculator.formatCost(totalCosts.cacheCreateCost),
              cacheReadCost: CostCalculator.formatCost(totalCosts.cacheReadCost),
              totalCost: CostCalculator.formatCost(totalCosts.totalCost)
            }
          },
          modelCosts: Object.values(modelCosts).sort((a, b) => b.costs.total - a.costs.total),
          pricingServiceStatus: pricingService.getStatus()
        }
      });
      return;
    }
    
    // 对于今日或本月，从Redis获取详细的模型统计
    const keys = await client.keys(pattern);
    
    for (const key of keys) {
      const match = key.match(period === 'today' ? 
        /usage:model:daily:(.+):\d{4}-\d{2}-\d{2}$/ : 
        /usage:model:monthly:(.+):\d{4}-\d{2}$/
      );
      
      if (!match) continue;
      
      const model = match[1];
      const data = await client.hgetall(key);
      
      if (data && Object.keys(data).length > 0) {
        const usage = {
          input_tokens: parseInt(data.inputTokens) || 0,
          output_tokens: parseInt(data.outputTokens) || 0,
          cache_creation_input_tokens: parseInt(data.cacheCreateTokens) || 0,
          cache_read_input_tokens: parseInt(data.cacheReadTokens) || 0
        };
        
        const costResult = CostCalculator.calculateCost(usage, model);
        
        // 累加总费用
        totalCosts.inputCost += costResult.costs.input;
        totalCosts.outputCost += costResult.costs.output;
        totalCosts.cacheCreateCost += costResult.costs.cacheWrite;
        totalCosts.cacheReadCost += costResult.costs.cacheRead;
        totalCosts.totalCost += costResult.costs.total;
        
        // 记录模型费用
        modelCosts[model] = {
          model,
          requests: parseInt(data.requests) || 0,
          usage,
          costs: costResult.costs,
          formatted: costResult.formatted,
          usingDynamicPricing: costResult.usingDynamicPricing
        };
      }
    }
    
    res.json({
      success: true,
      data: {
        period,
        totalCosts: {
          ...totalCosts,
          formatted: {
            inputCost: CostCalculator.formatCost(totalCosts.inputCost),
            outputCost: CostCalculator.formatCost(totalCosts.outputCost),
            cacheCreateCost: CostCalculator.formatCost(totalCosts.cacheCreateCost),
            cacheReadCost: CostCalculator.formatCost(totalCosts.cacheReadCost),
            totalCost: CostCalculator.formatCost(totalCosts.totalCost)
          }
        },
        modelCosts: Object.values(modelCosts).sort((a, b) => b.costs.total - a.costs.total),
        pricingServiceStatus: pricingService.getStatus()
      }
    });
  } catch (error) {
    logger.error('❌ Failed to calculate usage costs:', error);
    res.status(500).json({ error: 'Failed to calculate usage costs', message: error.message });
  }
});

module.exports = router;