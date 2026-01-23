# 🐳 使用官方 Node.js 18 Alpine 镜像
FROM node:18-alpine

# 📋 设置标签
LABEL maintainer="claude-relay-service@example.com"
LABEL description="Claude Code API Relay Service"
LABEL version="1.0.0"

# 🔧 安装系统依赖
RUN apk add --no-cache \
    curl \
    dumb-init \
    && rm -rf /var/cache/apk/*

# 👤 创建应用用户
RUN addgroup -g 1001 -S nodejs && \
    adduser -S claude -u 1001 -G nodejs

# 📁 设置工作目录
WORKDIR /app

# 📦 复制 package 文件
COPY package*.json ./

# 🔽 安装依赖 (生产环境)
RUN npm ci --only=production && \
    npm cache clean --force

# 📋 复制应用代码
COPY --chown=claude:nodejs . .

# 📁 创建必要目录
RUN mkdir -p logs data temp && \
    chown -R claude:nodejs logs data temp

# 🔐 切换到非 root 用户
USER claude

# 🌐 暴露端口
EXPOSE 3000

# 🏥 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# 🚀 启动应用
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "src/app.js"]