#!/usr/bin/env node

const https = require('https');
const { performance } = require('perf_hooks');

// 监控脚本：检查Claude Relay Service健康状态
class ServiceMonitor {
  constructor() {
    this.endpoints = [
      { name: 'Health Check', url: 'http://127.0.0.1:9000/health' },
      { name: 'Claude API', url: 'https://api.anthropic.com/v1/models' }
    ];
  }

  async checkEndpoint(endpoint) {
    return new Promise((resolve) => {
      const startTime = performance.now();
      const url = new URL(endpoint.url);
      
      const options = {
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname,
        method: 'GET',
        timeout: 10000
      };

      const protocol = url.protocol === 'https:' ? https : require('http');
      
      const req = protocol.request(options, (res) => {
        const endTime = performance.now();
        const responseTime = Math.round(endTime - startTime);
        
        resolve({
          name: endpoint.name,
          status: 'success',
          statusCode: res.statusCode,
          responseTime: `${responseTime}ms`,
          timestamp: new Date().toISOString()
        });
      });

      req.on('error', (error) => {
        const endTime = performance.now();
        const responseTime = Math.round(endTime - startTime);
        
        resolve({
          name: endpoint.name,
          status: 'error',
          error: error.message,
          responseTime: `${responseTime}ms`,
          timestamp: new Date().toISOString()
        });
      });

      req.on('timeout', () => {
        req.destroy();
        resolve({
          name: endpoint.name,
          status: 'timeout',
          error: 'Request timeout (>10s)',
          responseTime: '>10000ms',
          timestamp: new Date().toISOString()
        });
      });

      req.end();
    });
  }

  async runChecks() {
    console.log('🔍 Running service health checks...\n');
    
    const results = await Promise.all(
      this.endpoints.map(endpoint => this.checkEndpoint(endpoint))
    );

    results.forEach(result => {
      const status = result.status === 'success' ? '✅' : '❌';
      console.log(`${status} ${result.name}:`);
      console.log(`   Status: ${result.status}`);
      if (result.statusCode) console.log(`   HTTP Code: ${result.statusCode}`);
      console.log(`   Response Time: ${result.responseTime}`);
      if (result.error) console.log(`   Error: ${result.error}`);
      console.log(`   Time: ${result.timestamp}\n`);
    });

    const allHealthy = results.every(r => r.status === 'success');
    console.log(allHealthy ? '🎉 All services healthy!' : '⚠️  Some services have issues');
    
    return allHealthy;
  }

  async runContinuousMonitoring(intervalMinutes = 5) {
    console.log(`🔄 Starting continuous monitoring (every ${intervalMinutes} minutes)...\n`);
    
    const runCheck = async () => {
      try {
        await this.runChecks();
      } catch (error) {
        console.error('❌ Monitor check failed:', error.message);
      }
    };

    // 立即运行一次
    await runCheck();
    
    // 设置定时检查
    setInterval(runCheck, intervalMinutes * 60 * 1000);
  }
}

// 命令行使用
if (require.main === module) {
  const monitor = new ServiceMonitor();
  
  const args = process.argv.slice(2);
  const command = args[0] || 'check';
  
  switch (command) {
    case 'check':
      monitor.runChecks();
      break;
    case 'watch':
      const interval = parseInt(args[1]) || 5;
      monitor.runContinuousMonitoring(interval);
      break;
    default:
      console.log('Usage:');
      console.log('  node monitor.js check        # Run once');
      console.log('  node monitor.js watch [min]  # Continuous monitoring');
  }
}

module.exports = ServiceMonitor; 