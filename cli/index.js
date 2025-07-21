#!/usr/bin/env node

const { Command } = require('commander');
const inquirer = require('inquirer');
const chalk = require('chalk');
const ora = require('ora');
const Table = require('table').table;
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const config = require('../config/config');
const redis = require('../src/models/redis');
const apiKeyService = require('../src/services/apiKeyService');
const claudeAccountService = require('../src/services/claudeAccountService');

const program = new Command();

// 🎨 样式
const styles = {
  title: chalk.bold.blue,
  success: chalk.green,
  error: chalk.red,
  warning: chalk.yellow,
  info: chalk.cyan,
  dim: chalk.dim
};

// 🔧 初始化
async function initialize() {
  const spinner = ora('正在连接 Redis...').start();
  try {
    await redis.connect();
    spinner.succeed('Redis 连接成功');
  } catch (error) {
    spinner.fail('Redis 连接失败');
    console.error(styles.error(error.message));
    process.exit(1);
  }
}

// 🔐 管理员账户管理
program
  .command('admin')
  .description('管理员账户操作')
  .action(async () => {
    await initialize();
    
    // 直接执行创建初始管理员
    await createInitialAdmin();
    
    await redis.disconnect();
  });


// 📊 系统状态
program
  .command('status')
  .description('查看系统状态')
  .action(async () => {
    await initialize();
    
    const spinner = ora('正在获取系统状态...').start();
    
    try {
      const [systemStats, apiKeys, accounts] = await Promise.all([
        redis.getSystemStats(),
        apiKeyService.getAllApiKeys(),
        claudeAccountService.getAllAccounts()
      ]);

      spinner.succeed('系统状态获取成功');

      console.log(styles.title('\n📊 系统状态概览\n'));
      
      const statusData = [
        ['项目', '数量', '状态'],
        ['API Keys', apiKeys.length, `${apiKeys.filter(k => k.isActive).length} 活跃`],
        ['Claude 账户', accounts.length, `${accounts.filter(a => a.isActive).length} 活跃`],
        ['Redis 连接', redis.isConnected ? '已连接' : '未连接', redis.isConnected ? '🟢' : '🔴'],
        ['运行时间', `${Math.floor(process.uptime() / 60)} 分钟`, '🕐']
      ];

      console.log(table(statusData));

      // 使用统计
      const totalTokens = apiKeys.reduce((sum, key) => sum + (key.usage?.total?.tokens || 0), 0);
      const totalRequests = apiKeys.reduce((sum, key) => sum + (key.usage?.total?.requests || 0), 0);

      console.log(styles.title('\n📈 使用统计\n'));
      console.log(`总 Token 使用量: ${styles.success(totalTokens.toLocaleString())}`);
      console.log(`总请求数: ${styles.success(totalRequests.toLocaleString())}`);

    } catch (error) {
      spinner.fail('获取系统状态失败');
      console.error(styles.error(error.message));
    }
    
    await redis.disconnect();
  });


// 实现具体功能函数

async function createInitialAdmin() {
  console.log(styles.title('\n🔐 创建初始管理员账户\n'));
  
  // 检查是否已存在 init.json
  const initFilePath = path.join(__dirname, '..', 'data', 'init.json');
  if (fs.existsSync(initFilePath)) {
    const existingData = JSON.parse(fs.readFileSync(initFilePath, 'utf8'));
    console.log(styles.warning('⚠️  检测到已存在管理员账户！'));
    console.log(`   用户名: ${existingData.adminUsername}`);
    console.log(`   创建时间: ${new Date(existingData.initializedAt).toLocaleString()}`);
    
    const { overwrite } = await inquirer.prompt([{
      type: 'confirm',
      name: 'overwrite',
      message: '是否覆盖现有管理员账户？',
      default: false
    }]);
    
    if (!overwrite) {
      console.log(styles.info('ℹ️  已取消创建'));
      return;
    }
  }
  
  const adminData = await inquirer.prompt([
    {
      type: 'input',
      name: 'username',
      message: '用户名:',
      default: 'admin',
      validate: input => input.length >= 3 || '用户名至少3个字符'
    },
    {
      type: 'password',
      name: 'password',
      message: '密码:',
      validate: input => input.length >= 8 || '密码至少8个字符'
    },
    {
      type: 'password',
      name: 'confirmPassword',
      message: '确认密码:',
      validate: (input, answers) => input === answers.password || '密码不匹配'
    }
  ]);

  const spinner = ora('正在创建管理员账户...').start();
  
  try {
    // 1. 先更新 init.json（唯一真实数据源）
    const initData = {
      initializedAt: new Date().toISOString(),
      adminUsername: adminData.username,
      adminPassword: adminData.password, // 保存明文密码
      version: '1.0.0',
      updatedAt: new Date().toISOString()
    };
    
    // 确保 data 目录存在
    const dataDir = path.join(__dirname, '..', 'data');
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }
    
    // 写入文件
    fs.writeFileSync(initFilePath, JSON.stringify(initData, null, 2));
    
    // 2. 再更新 Redis 缓存
    const passwordHash = await bcrypt.hash(adminData.password, 12);
    
    const credentials = {
      username: adminData.username,
      passwordHash,
      createdAt: new Date().toISOString(),
      lastLogin: null,
      updatedAt: new Date().toISOString()
    };

    await redis.setSession('admin_credentials', credentials, 0); // 永不过期
    
    spinner.succeed('管理员账户创建成功');
    console.log(`${styles.success('✅')} 用户名: ${adminData.username}`);
    console.log(`${styles.success('✅')} 密码: ${adminData.password}`);
    console.log(`${styles.info('ℹ️')} 请妥善保管登录凭据`);
    console.log(`${styles.info('ℹ️')} 凭据已保存到: ${initFilePath}`);
    console.log(`${styles.warning('⚠️')} 如果服务正在运行，请重启服务以加载新凭据`);

  } catch (error) {
    spinner.fail('创建管理员账户失败');
    console.error(styles.error(error.message));
  }
}






async function listClaudeAccounts() {
  const spinner = ora('正在获取 Claude 账户...').start();
  
  try {
    const accounts = await claudeAccountService.getAllAccounts();
    spinner.succeed(`找到 ${accounts.length} 个 Claude 账户`);

    if (accounts.length === 0) {
      console.log(styles.warning('没有找到任何 Claude 账户'));
      return;
    }

    const tableData = [
      ['ID', '名称', '邮箱', '状态', '代理', '最后使用']
    ];

    accounts.forEach(account => {
      let statusText;
      if (!account.isActive) {
        statusText = '🔴 禁用';
      } else if (account.status === 'active') {
        statusText = '🟢 活跃';
      } else if (account.status === 'error') {
        statusText = '❌ 错误';
      } else {
        statusText = '🟡 待激活';
      }
      
      tableData.push([
        account.id.substring(0, 8) + '...',
        account.name,
        account.email || '-',
        statusText,
        account.proxy ? '🌐 是' : '-',
        account.lastUsedAt ? new Date(account.lastUsedAt).toLocaleDateString() : '-'
      ]);
    });

    console.log('\n🏢 Claude 账户列表:\n');
    console.log(table(tableData));

  } catch (error) {
    spinner.fail('获取 Claude 账户失败');
    console.error(styles.error(error.message));
  }
}

// 程序信息
program
  .name('claude-relay-cli')
  .description('Claude Relay Service 命令行管理工具')
  .version('1.0.0');

// 解析命令行参数
program.parse();

// 如果没有提供命令，显示帮助
if (!process.argv.slice(2).length) {
  console.log(styles.title('🚀 Claude Relay Service CLI\n'));
  console.log('使用以下命令管理服务:\n');
  console.log('  claude-relay-cli admin         - 创建初始管理员账户');
  console.log('  claude-relay-cli status        - 查看系统状态');
  console.log('\n使用 --help 查看详细帮助信息');
}