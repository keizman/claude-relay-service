const https = require('https');
const zlib = require('zlib');
const fs = require('fs');
const path = require('path');
const { SocksProxyAgent } = require('socks-proxy-agent');
const { HttpsProxyAgent } = require('https-proxy-agent');
const claudeAccountService = require('./claudeAccountService');
const sessionHelper = require('../utils/sessionHelper');
const logger = require('../utils/logger');
const config = require('../../config/config');

class ClaudeRelayService {
  constructor() {
    this.claudeApiUrl = config.claude.apiUrl;
    this.apiVersion = config.claude.apiVersion;
    this.betaHeader = config.claude.betaHeader;
    this.systemPrompt = config.claude.systemPrompt;
  }

  // 🚀 转发请求到Claude API
  async relayRequest(requestBody, apiKeyData, clientRequest, clientResponse, clientHeaders) {
    let upstreamRequest = null;
    
    try {
      // 调试日志：查看API Key数据
      logger.info('🔍 API Key data received:', {
        apiKeyName: apiKeyData.name,
        enableModelRestriction: apiKeyData.enableModelRestriction,
        restrictedModels: apiKeyData.restrictedModels,
        requestedModel: requestBody.model
      });

      // 检查模型限制
      if (apiKeyData.enableModelRestriction && apiKeyData.restrictedModels && apiKeyData.restrictedModels.length > 0) {
        const requestedModel = requestBody.model;
        logger.info(`🔒 Model restriction check - Requested model: ${requestedModel}, Restricted models: ${JSON.stringify(apiKeyData.restrictedModels)}`);
        
        if (requestedModel && apiKeyData.restrictedModels.includes(requestedModel)) {
          logger.warn(`🚫 Model restriction violation for key ${apiKeyData.name}: Attempted to use restricted model ${requestedModel}`);
          return {
            statusCode: 403,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              error: {
                type: 'forbidden',
                message: '暂无该模型访问权限'
              }
            })
          };
        }
      }
      
      // 生成会话哈希用于sticky会话
      const sessionHash = sessionHelper.generateSessionHash(requestBody);
      
      // 选择可用的Claude账户（支持专属绑定和sticky会话）
      const accountId = await claudeAccountService.selectAccountForApiKey(apiKeyData, sessionHash);
      
      logger.info(`📤 Processing API request for key: ${apiKeyData.name || apiKeyData.id}, account: ${accountId}${sessionHash ? `, session: ${sessionHash}` : ''}`);
      
      // 获取有效的访问token
      const accessToken = await claudeAccountService.getValidAccessToken(accountId);
      
      // 处理请求体
      const processedBody = this._processRequestBody(requestBody);
      
      // 获取代理配置
      const proxyAgent = await this._getProxyAgent(accountId);
      
      // 设置客户端断开监听器
      const handleClientDisconnect = () => {
        logger.info('🔌 Client disconnected, aborting upstream request');
        if (upstreamRequest && !upstreamRequest.destroyed) {
          upstreamRequest.destroy();
        }
      };
      
      // 监听客户端断开事件
      if (clientRequest) {
        clientRequest.once('close', handleClientDisconnect);
      }
      if (clientResponse) {
        clientResponse.once('close', handleClientDisconnect);
      }
      
      // 发送请求到Claude API（传入回调以获取请求对象）
      const response = await this._makeClaudeRequest(
        processedBody, 
        accessToken, 
        proxyAgent,
        clientHeaders,
        (req) => { upstreamRequest = req; }
      );
      
      // 移除监听器（请求成功完成）
      if (clientRequest) {
        clientRequest.removeListener('close', handleClientDisconnect);
      }
      if (clientResponse) {
        clientResponse.removeListener('close', handleClientDisconnect);
      }
      
      // 检查响应是否为限流错误
      if (response.statusCode !== 200 && response.statusCode !== 201) {
        let isRateLimited = false;
        try {
          const responseBody = typeof response.body === 'string' ? JSON.parse(response.body) : response.body;
          if (responseBody && responseBody.error && responseBody.error.message && 
              responseBody.error.message.toLowerCase().includes('exceed your account\'s rate limit')) {
            isRateLimited = true;
          }
        } catch (e) {
          // 如果解析失败，检查原始字符串
          if (response.body && response.body.toLowerCase().includes('exceed your account\'s rate limit')) {
            isRateLimited = true;
          }
        }
        
        if (isRateLimited) {
          logger.warn(`🚫 Rate limit detected for account ${accountId}, status: ${response.statusCode}`);
          // 标记账号为限流状态并删除粘性会话映射
          await claudeAccountService.markAccountRateLimited(accountId, sessionHash);
        }
      } else if (response.statusCode === 200 || response.statusCode === 201) {
        // 如果请求成功，检查并移除限流状态
        const isRateLimited = await claudeAccountService.isAccountRateLimited(accountId);
        if (isRateLimited) {
          await claudeAccountService.removeAccountRateLimit(accountId);
        }
      }
      
      // 记录成功的API调用
      const inputTokens = requestBody.messages ? 
        requestBody.messages.reduce((sum, msg) => sum + (msg.content?.length || 0), 0) / 4 : 0; // 粗略估算
      const outputTokens = response.content ? 
        response.content.reduce((sum, content) => sum + (content.text?.length || 0), 0) / 4 : 0;
      
      logger.info(`✅ API request completed - Key: ${apiKeyData.name}, Account: ${accountId}, Model: ${requestBody.model}, Input: ~${Math.round(inputTokens)} tokens, Output: ~${Math.round(outputTokens)} tokens`);
      
      return response;
    } catch (error) {
      logger.error(`❌ Claude relay request failed for key: ${apiKeyData.name || apiKeyData.id}:`, error.message);
      throw error;
    }
  }

  // 🔄 处理请求体
  _processRequestBody(body) {
    if (!body) return body;

    // 深拷贝请求体
    const processedBody = JSON.parse(JSON.stringify(body));

    // 验证并限制max_tokens参数
    this._validateAndLimitMaxTokens(processedBody);

    // 移除cache_control中的ttl字段
    this._stripTtlFromCacheControl(processedBody);

    // 只有在配置了系统提示时才添加
    if (this.systemPrompt && this.systemPrompt.trim()) {
      const systemPrompt = {
        type: 'text',
        text: this.systemPrompt
      };

      if (processedBody.system) {
        if (Array.isArray(processedBody.system)) {
          // 如果system数组存在但为空，或者没有有效内容，则添加系统提示
          const hasValidContent = processedBody.system.some(item => 
            item && item.text && item.text.trim()
          );
          if (!hasValidContent) {
            processedBody.system = [systemPrompt];
          } else {
            processedBody.system.unshift(systemPrompt);
          }
        } else {
          throw new Error('system field must be an array');
        }
      } else {
        processedBody.system = [systemPrompt];
      }
    } else {
      // 如果没有配置系统提示，且system字段为空，则删除它
      if (processedBody.system && Array.isArray(processedBody.system)) {
        const hasValidContent = processedBody.system.some(item => 
          item && item.text && item.text.trim()
        );
        if (!hasValidContent) {
          delete processedBody.system;
        }
      }
    }

    return processedBody;
  }

  // 🔢 验证并限制max_tokens参数
  _validateAndLimitMaxTokens(body) {
    if (!body || !body.max_tokens) return;

    try {
      // 读取模型定价配置文件
      const pricingFilePath = path.join(__dirname, '../../data/model_pricing.json');
      
      if (!fs.existsSync(pricingFilePath)) {
        logger.warn('⚠️ Model pricing file not found, skipping max_tokens validation');
        return;
      }

      const pricingData = JSON.parse(fs.readFileSync(pricingFilePath, 'utf8'));
      const model = body.model || 'claude-sonnet-4-20250514';
      
      // 查找对应模型的配置
      const modelConfig = pricingData[model];
      
      if (!modelConfig) {
        logger.debug(`🔍 Model ${model} not found in pricing file, skipping max_tokens validation`);
        return;
      }

      // 获取模型的最大token限制
      const maxLimit = modelConfig.max_tokens || modelConfig.max_output_tokens;
      
      if (!maxLimit) {
        logger.debug(`🔍 No max_tokens limit found for model ${model}, skipping validation`);
        return;
      }

      // 检查并调整max_tokens
      if (body.max_tokens > maxLimit) {
        logger.warn(`⚠️ max_tokens ${body.max_tokens} exceeds limit ${maxLimit} for model ${model}, adjusting to ${maxLimit}`);
        body.max_tokens = maxLimit;
      }
    } catch (error) {
      logger.error('❌ Failed to validate max_tokens from pricing file:', error);
      // 如果文件读取失败，不进行校验，让请求继续处理
    }
  }

  // 🧹 移除TTL字段
  _stripTtlFromCacheControl(body) {
    if (!body || typeof body !== 'object') return;

    const processContentArray = (contentArray) => {
      if (!Array.isArray(contentArray)) return;
      
      contentArray.forEach(item => {
        if (item && typeof item === 'object' && item.cache_control) {
          if (item.cache_control.ttl) {
            delete item.cache_control.ttl;
            logger.debug('🧹 Removed ttl from cache_control');
          }
        }
      });
    };

    if (Array.isArray(body.system)) {
      processContentArray(body.system);
    }

    if (Array.isArray(body.messages)) {
      body.messages.forEach(message => {
        if (message && Array.isArray(message.content)) {
          processContentArray(message.content);
        }
      });
    }
  }

  // 🌐 获取代理Agent
  async _getProxyAgent(accountId) {
    try {
      const accountData = await claudeAccountService.getAllAccounts();
      const account = accountData.find(acc => acc.id === accountId);
      
      if (!account || !account.proxy) {
        return null;
      }

      const proxy = account.proxy;
      
      if (proxy.type === 'socks5') {
        const auth = proxy.username && proxy.password ? `${proxy.username}:${proxy.password}@` : '';
        const socksUrl = `socks5://${auth}${proxy.host}:${proxy.port}`;
        return new SocksProxyAgent(socksUrl);
      } else if (proxy.type === 'socks5h') {
        const auth = proxy.username && proxy.password ? `${proxy.username}:${proxy.password}@` : '';
        const socksUrl = `socks5h://${auth}${proxy.host}:${proxy.port}`;
        return new SocksProxyAgent(socksUrl);
      } else if (proxy.type === 'http' || proxy.type === 'https') {
        const auth = proxy.username && proxy.password ? `${proxy.username}:${proxy.password}@` : '';
        const httpUrl = `${proxy.type}://${auth}${proxy.host}:${proxy.port}`;
        return new HttpsProxyAgent(httpUrl);
      }
    } catch (error) {
      logger.warn('⚠️ Failed to create proxy agent:', error);
    }

    return null;
  }

  // 🔧 过滤客户端请求头
  _filterClientHeaders(clientHeaders) {
    // 需要移除的敏感 headers
    const sensitiveHeaders = [
      'x-api-key',
      'authorization',
      'host',
      'content-length',
      'connection',
      'proxy-authorization',
      'content-encoding',
      'transfer-encoding'
    ];
    
    const filteredHeaders = {};
    
    // 转发客户端的非敏感 headers
    Object.keys(clientHeaders || {}).forEach(key => {
      const lowerKey = key.toLowerCase();
      if (!sensitiveHeaders.includes(lowerKey)) {
        filteredHeaders[key] = clientHeaders[key];
      }
    });
    
    return filteredHeaders;
  }

  // 🔗 发送请求到Claude API
  async _makeClaudeRequest(body, accessToken, proxyAgent, clientHeaders, onRequest) {
    return new Promise((resolve, reject) => {
      const url = new URL(this.claudeApiUrl);
      
      // 获取过滤后的客户端 headers
      const filteredHeaders = this._filterClientHeaders(clientHeaders);
      
      const options = {
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`,
          'anthropic-version': this.apiVersion,
          ...filteredHeaders
        },
        agent: proxyAgent,
        timeout: config.proxy.timeout
      };
      
      // 如果客户端没有提供 User-Agent，使用默认值
      if (!filteredHeaders['User-Agent'] && !filteredHeaders['user-agent']) {
        options.headers['User-Agent'] = 'claude-cli/1.0.53 (external, cli)';
      }

      if (this.betaHeader) {
        options.headers['anthropic-beta'] = this.betaHeader;
      }

      const req = https.request(options, (res) => {
        let responseData = Buffer.alloc(0);
        
        res.on('data', (chunk) => {
          responseData = Buffer.concat([responseData, chunk]);
        });
        
        res.on('end', () => {
          try {
            let bodyString = '';
            
            // 根据Content-Encoding处理响应数据
            const contentEncoding = res.headers['content-encoding'];
            if (contentEncoding === 'gzip') {
              try {
                bodyString = zlib.gunzipSync(responseData).toString('utf8');
              } catch (unzipError) {
                logger.error('❌ Failed to decompress gzip response:', unzipError);
                bodyString = responseData.toString('utf8');
              }
            } else if (contentEncoding === 'deflate') {
              try {
                bodyString = zlib.inflateSync(responseData).toString('utf8');
              } catch (unzipError) {
                logger.error('❌ Failed to decompress deflate response:', unzipError);
                bodyString = responseData.toString('utf8');
              }
            } else {
              bodyString = responseData.toString('utf8');
            }
            
            const response = {
              statusCode: res.statusCode,
              headers: res.headers,
              body: bodyString
            };
            
            logger.debug(`🔗 Claude API response: ${res.statusCode}`);
            
            resolve(response);
          } catch (error) {
            logger.error('❌ Failed to parse Claude API response:', error);
            reject(error);
          }
        });
      });
      
      // 如果提供了 onRequest 回调，传递请求对象
      if (onRequest && typeof onRequest === 'function') {
        onRequest(req);
      }

      req.on('error', (error) => {
        logger.error('❌ Claude API request error:', error.message, {
          code: error.code,
          errno: error.errno,
          syscall: error.syscall,
          address: error.address,
          port: error.port
        });
        
        // 根据错误类型提供更具体的错误信息
        let errorMessage = 'Upstream request failed';
        if (error.code === 'ECONNRESET') {
          errorMessage = 'Connection reset by Claude API server';
        } else if (error.code === 'ENOTFOUND') {
          errorMessage = 'Unable to resolve Claude API hostname';
        } else if (error.code === 'ECONNREFUSED') {
          errorMessage = 'Connection refused by Claude API server';
        } else if (error.code === 'ETIMEDOUT') {
          errorMessage = 'Connection timed out to Claude API server';
        }
        
        reject(new Error(errorMessage));
      });

      req.on('timeout', () => {
        req.destroy();
        logger.error('❌ Claude API request timeout');
        reject(new Error('Request timeout'));
      });

      // 写入请求体
      req.write(JSON.stringify(body));
      req.end();
    });
  }

  // 🌊 处理流式响应（带usage数据捕获）
  async relayStreamRequestWithUsageCapture(requestBody, apiKeyData, responseStream, clientHeaders, usageCallback) {
    try {
      // 调试日志：查看API Key数据（流式请求）
      logger.info('🔍 [Stream] API Key data received:', {
        apiKeyName: apiKeyData.name,
        enableModelRestriction: apiKeyData.enableModelRestriction,
        restrictedModels: apiKeyData.restrictedModels,
        requestedModel: requestBody.model
      });

      // 检查模型限制
      if (apiKeyData.enableModelRestriction && apiKeyData.restrictedModels && apiKeyData.restrictedModels.length > 0) {
        const requestedModel = requestBody.model;
        logger.info(`🔒 [Stream] Model restriction check - Requested model: ${requestedModel}, Restricted models: ${JSON.stringify(apiKeyData.restrictedModels)}`);
        
        if (requestedModel && apiKeyData.restrictedModels.includes(requestedModel)) {
          logger.warn(`🚫 Model restriction violation for key ${apiKeyData.name}: Attempted to use restricted model ${requestedModel}`);
          
          // 对于流式响应，需要写入错误并结束流
          const errorResponse = JSON.stringify({
            error: {
              type: 'forbidden',
              message: '暂无该模型访问权限'
            }
          });
          
          responseStream.writeHead(403, { 'Content-Type': 'application/json' });
          responseStream.end(errorResponse);
          return;
        }
      }
      
      // 生成会话哈希用于sticky会话
      const sessionHash = sessionHelper.generateSessionHash(requestBody);
      
      // 选择可用的Claude账户（支持专属绑定和sticky会话）
      const accountId = await claudeAccountService.selectAccountForApiKey(apiKeyData, sessionHash);
      
      logger.info(`📡 Processing streaming API request with usage capture for key: ${apiKeyData.name || apiKeyData.id}, account: ${accountId}${sessionHash ? `, session: ${sessionHash}` : ''}`);
      
      // 获取有效的访问token
      const accessToken = await claudeAccountService.getValidAccessToken(accountId);
      
      // 处理请求体
      const processedBody = this._processRequestBody(requestBody);
      
      // 获取代理配置
      const proxyAgent = await this._getProxyAgent(accountId);
      
      // 发送流式请求并捕获usage数据
      return await this._makeClaudeStreamRequestWithUsageCapture(processedBody, accessToken, proxyAgent, clientHeaders, responseStream, usageCallback, accountId, sessionHash);
    } catch (error) {
      logger.error('❌ Claude stream relay with usage capture failed:', error);
      throw error;
    }
  }

  // 🌊 发送流式请求到Claude API（带usage数据捕获）
  async _makeClaudeStreamRequestWithUsageCapture(body, accessToken, proxyAgent, clientHeaders, responseStream, usageCallback, accountId, sessionHash) {
    return new Promise((resolve, reject) => {
      const url = new URL(this.claudeApiUrl);
      
      // 获取过滤后的客户端 headers
      const filteredHeaders = this._filterClientHeaders(clientHeaders);
      
      const options = {
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`,
          'anthropic-version': this.apiVersion,
          ...filteredHeaders
        },
        agent: proxyAgent,
        timeout: config.proxy.timeout
      };
      
      // 如果客户端没有提供 User-Agent，使用默认值
      if (!filteredHeaders['User-Agent'] && !filteredHeaders['user-agent']) {
        options.headers['User-Agent'] = 'claude-cli/1.0.53 (external, cli)';
      }

      if (this.betaHeader) {
        options.headers['anthropic-beta'] = this.betaHeader;
      }

      const req = https.request(options, (res) => {
        // 设置响应头
        responseStream.statusCode = res.statusCode;
        Object.keys(res.headers).forEach(key => {
          responseStream.setHeader(key, res.headers[key]);
        });

        let buffer = '';
        let finalUsageReported = false; // 防止重复统计的标志
        let collectedUsageData = {}; // 收集来自不同事件的usage数据
        let rateLimitDetected = false; // 限流检测标志
        
        // 监听数据块，解析SSE并寻找usage信息
        res.on('data', (chunk) => {
          const chunkStr = chunk.toString();
          
          buffer += chunkStr;
          
          // 处理完整的SSE行
          const lines = buffer.split('\n');
          buffer = lines.pop() || ''; // 保留最后的不完整行
          
          // 转发已处理的完整行到客户端
          if (lines.length > 0) {
            const linesToForward = lines.join('\n') + (lines.length > 0 ? '\n' : '');
            responseStream.write(linesToForward);
          }
          
          for (const line of lines) {
            // 解析SSE数据寻找usage信息
            if (line.startsWith('data: ') && line.length > 6) {
              try {
                const jsonStr = line.slice(6);
                const data = JSON.parse(jsonStr);
                
                // 收集来自不同事件的usage数据
                if (data.type === 'message_start' && data.message && data.message.usage) {
                  // message_start包含input tokens、cache tokens和模型信息
                  collectedUsageData.input_tokens = data.message.usage.input_tokens || 0;
                  collectedUsageData.cache_creation_input_tokens = data.message.usage.cache_creation_input_tokens || 0;
                  collectedUsageData.cache_read_input_tokens = data.message.usage.cache_read_input_tokens || 0;
                  collectedUsageData.model = data.message.model;
                  
                  logger.info('📊 Collected input/cache data from message_start:', JSON.stringify(collectedUsageData));
                }
                
                // message_delta包含最终的output tokens
                if (data.type === 'message_delta' && data.usage && data.usage.output_tokens !== undefined) {
                  collectedUsageData.output_tokens = data.usage.output_tokens || 0;
                  
                  logger.info('📊 Collected output data from message_delta:', JSON.stringify(collectedUsageData));
                  
                  // 如果已经收集到了input数据，现在有了output数据，可以统计了
                  if (collectedUsageData.input_tokens !== undefined && !finalUsageReported) {
                    logger.info('🎯 Complete usage data collected, triggering callback');
                    usageCallback(collectedUsageData);
                    finalUsageReported = true;
                  }
                }
                
                // 检查是否有限流错误
                if (data.type === 'error' && data.error && data.error.message && 
                    data.error.message.toLowerCase().includes('exceed your account\'s rate limit')) {
                  rateLimitDetected = true;
                  logger.warn(`🚫 Rate limit detected in stream for account ${accountId}`);
                }
                
              } catch (parseError) {
                // 忽略JSON解析错误，继续处理
                logger.debug('🔍 SSE line not JSON or no usage data:', line.slice(0, 100));
              }
            }
          }
        });
        
        res.on('end', async () => {
          // 处理缓冲区中剩余的数据
          if (buffer.trim()) {
            responseStream.write(buffer);
          }
          responseStream.end();
          
          // 检查是否捕获到usage数据
          if (!finalUsageReported) {
            logger.warn('⚠️ Stream completed but no usage data was captured! This indicates a problem with SSE parsing or Claude API response format.');
          }
          
          // 处理限流状态
          if (rateLimitDetected || res.statusCode === 429) {
            // 标记账号为限流状态并删除粘性会话映射
            await claudeAccountService.markAccountRateLimited(accountId, sessionHash);
          } else if (res.statusCode === 200) {
            // 如果请求成功，检查并移除限流状态
            const isRateLimited = await claudeAccountService.isAccountRateLimited(accountId);
            if (isRateLimited) {
              await claudeAccountService.removeAccountRateLimit(accountId);
            }
          }
          
          logger.debug('🌊 Claude stream response with usage capture completed');
          resolve();
        });
      });

      req.on('error', (error) => {
        logger.error('❌ Claude stream request error:', error.message, {
          code: error.code,
          errno: error.errno,
          syscall: error.syscall
        });
        
        // 根据错误类型提供更具体的错误信息
        let errorMessage = 'Upstream request failed';
        let statusCode = 500;
        if (error.code === 'ECONNRESET') {
          errorMessage = 'Connection reset by Claude API server';
          statusCode = 502;
        } else if (error.code === 'ENOTFOUND') {
          errorMessage = 'Unable to resolve Claude API hostname';
          statusCode = 502;
        } else if (error.code === 'ECONNREFUSED') {
          errorMessage = 'Connection refused by Claude API server';
          statusCode = 502;
        } else if (error.code === 'ETIMEDOUT') {
          errorMessage = 'Connection timed out to Claude API server';
          statusCode = 504;
        }
        
        if (!responseStream.headersSent) {
          responseStream.writeHead(statusCode, { 
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive'
          });
        }
        
        if (!responseStream.destroyed) {
          // 发送 SSE 错误事件
          responseStream.write('event: error\n');
          responseStream.write(`data: ${JSON.stringify({ 
            error: errorMessage,
            code: error.code,
            timestamp: new Date().toISOString()
          })}\n\n`);
          responseStream.end();
        }
        reject(error);
      });

      req.on('timeout', () => {
        req.destroy();
        logger.error('❌ Claude stream request timeout');
        if (!responseStream.headersSent) {
          responseStream.writeHead(504, { 
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive'
          });
        }
        if (!responseStream.destroyed) {
          // 发送 SSE 错误事件
          responseStream.write('event: error\n');
          responseStream.write(`data: ${JSON.stringify({ 
            error: 'Request timeout',
            code: 'TIMEOUT',
            timestamp: new Date().toISOString()
          })}\n\n`);
          responseStream.end();
        }
        reject(new Error('Request timeout'));
      });

      // 处理客户端断开连接
      responseStream.on('close', () => {
        logger.debug('🔌 Client disconnected, cleaning up stream');
        if (!req.destroyed) {
          req.destroy();
        }
      });

      // 写入请求体
      req.write(JSON.stringify(body));
      req.end();
    });
  }

  // 🌊 发送流式请求到Claude API
  async _makeClaudeStreamRequest(body, accessToken, proxyAgent, clientHeaders, responseStream) {
    return new Promise((resolve, reject) => {
      const url = new URL(this.claudeApiUrl);
      
      // 获取过滤后的客户端 headers
      const filteredHeaders = this._filterClientHeaders(clientHeaders);
      
      const options = {
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`,
          'anthropic-version': this.apiVersion,
          ...filteredHeaders
        },
        agent: proxyAgent,
        timeout: config.proxy.timeout
      };
      
      // 如果客户端没有提供 User-Agent，使用默认值
      if (!filteredHeaders['User-Agent'] && !filteredHeaders['user-agent']) {
        options.headers['User-Agent'] = 'claude-cli/1.0.53 (external, cli)';
      }

      if (this.betaHeader) {
        options.headers['anthropic-beta'] = this.betaHeader;
      }

      const req = https.request(options, (res) => {
        // 设置响应头
        responseStream.statusCode = res.statusCode;
        Object.keys(res.headers).forEach(key => {
          responseStream.setHeader(key, res.headers[key]);
        });

        // 管道响应数据
        res.pipe(responseStream);
        
        res.on('end', () => {
          logger.debug('🌊 Claude stream response completed');
          resolve();
        });
      });

      req.on('error', (error) => {
        logger.error('❌ Claude stream request error:', error.message, {
          code: error.code,
          errno: error.errno,
          syscall: error.syscall
        });
        
        // 根据错误类型提供更具体的错误信息
        let errorMessage = 'Upstream request failed';
        let statusCode = 500;
        if (error.code === 'ECONNRESET') {
          errorMessage = 'Connection reset by Claude API server';
          statusCode = 502;
        } else if (error.code === 'ENOTFOUND') {
          errorMessage = 'Unable to resolve Claude API hostname';
          statusCode = 502;
        } else if (error.code === 'ECONNREFUSED') {
          errorMessage = 'Connection refused by Claude API server';
          statusCode = 502;
        } else if (error.code === 'ETIMEDOUT') {
          errorMessage = 'Connection timed out to Claude API server';
          statusCode = 504;
        }
        
        if (!responseStream.headersSent) {
          responseStream.writeHead(statusCode, { 
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive'
          });
        }
        
        if (!responseStream.destroyed) {
          // 发送 SSE 错误事件
          responseStream.write('event: error\n');
          responseStream.write(`data: ${JSON.stringify({ 
            error: errorMessage,
            code: error.code,
            timestamp: new Date().toISOString()
          })}\n\n`);
          responseStream.end();
        }
        reject(error);
      });

      req.on('timeout', () => {
        req.destroy();
        logger.error('❌ Claude stream request timeout');
        if (!responseStream.headersSent) {
          responseStream.writeHead(504, { 
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive'
          });
        }
        if (!responseStream.destroyed) {
          // 发送 SSE 错误事件
          responseStream.write('event: error\n');
          responseStream.write(`data: ${JSON.stringify({ 
            error: 'Request timeout',
            code: 'TIMEOUT',
            timestamp: new Date().toISOString()
          })}\n\n`);
          responseStream.end();
        }
        reject(new Error('Request timeout'));
      });

      // 处理客户端断开连接
      responseStream.on('close', () => {
        logger.debug('🔌 Client disconnected, cleaning up stream');
        if (!req.destroyed) {
          req.destroy();
        }
      });

      // 写入请求体
      req.write(JSON.stringify(body));
      req.end();
    });
  }

  // 🔄 重试逻辑
  async _retryRequest(requestFunc, maxRetries = 3) {
    let lastError;
    
    for (let i = 0; i < maxRetries; i++) {
      try {
        return await requestFunc();
      } catch (error) {
        lastError = error;
        
        if (i < maxRetries - 1) {
          const delay = Math.pow(2, i) * 1000; // 指数退避
          logger.warn(`⏳ Retry ${i + 1}/${maxRetries} in ${delay}ms: ${error.message}`);
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }
    
    throw lastError;
  }

  // 🎯 健康检查
  async healthCheck() {
    try {
      const accounts = await claudeAccountService.getAllAccounts();
      const activeAccounts = accounts.filter(acc => acc.isActive && acc.status === 'active');
      
      return {
        healthy: activeAccounts.length > 0,
        activeAccounts: activeAccounts.length,
        totalAccounts: accounts.length,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error('❌ Health check failed:', error);
      return {
        healthy: false,
        error: error.message,
        timestamp: new Date().toISOString()
      };
    }
  }
}

module.exports = new ClaudeRelayService();