-- ============================================================
-- 全自动安全扫描引擎 — 数据库初始化脚本
-- ============================================================
-- 此脚本用于创建 SQL 注入靶场所需的 MySQL 数据库和测试数据。
--
-- 使用方法：
--   CMD:      mysql -u root -p --default-character-set=utf8mb4 < init_database.sql
--   PowerShell: Get-Content init_database.sql | mysql -u root -p --default-character-set=utf8mb4
--
-- 注意事项：
--   1. 请确保 MySQL 服务已启动
--   2. 数据库名、用户名、密码可在 config.py 中通过环境变量覆盖
--   3. 本脚本包含故意设计的测试数据，仅用于安全教学与研究
-- ============================================================

-- 强制客户端连接使用 UTF-8，避免中文数据插入时字符集错误
SET NAMES utf8mb4;

-- 创建数据库（若已存在则跳过）
CREATE DATABASE IF NOT EXISTS vuln_db
    DEFAULT CHARACTER SET utf8mb4
    DEFAULT COLLATE utf8mb4_unicode_ci;

USE vuln_db;

-- ============================================================
-- 1. 用户表 — SQL 注入靶场的核心测试目标
-- ============================================================
-- 靶场通过 f-string 拼接用户输入构造 SQL 语句，存在以下漏洞：
--   • Union 注入：id=1' UNION SELECT username, password_hash FROM users--
--   • 布尔盲注：id=1' and ascii(substr((select database()),1,1))>100--
--   • 错误回显：id=1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(...))x)--
-- ============================================================

DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id            INT PRIMARY KEY AUTO_INCREMENT  COMMENT '用户ID',
    username      VARCHAR(100) NOT NULL           COMMENT '用户名',
    email         VARCHAR(100) DEFAULT NULL       COMMENT '邮箱',
    password_hash VARCHAR(255) DEFAULT NULL       COMMENT '密码哈希值（演示用明文）',
    role          VARCHAR(50)  DEFAULT 'user'     COMMENT '角色：admin / user',
    created_at    DATETIME     DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户表（SQL 注入演示）';

-- 插入测试数据
INSERT INTO users (username, email, password_hash, role) VALUES
    ('admin',        'admin@example.com',       '5f4dcc3b5aa765d61d8327deb882cf99', 'admin'),
    ('zhangsan',     'zhangsan@test.com',       'e10adc3949ba59abbe56e057f20f883e', 'user'),
    ('lisi',         'lisi@test.com',           '21232f297a57a5a743894a0e4a801fc3', 'user'),
    ('wangwu',       'wangwu@test.com',         '827ccb0eea8a706c4c34a16891f84e7b', 'user'),
    ('security_ops', 'secops@company.com',      '25d55ad283aa400af464c76d713c07ad', 'admin'),
    ('developer01',  'dev01@company.com',       'e99a18c428cb38d5f260853678922e03', 'user'),
    ('dba_master',   'dba@company.com',         '202cb962ac59075b964b07152d234b70', 'admin');

-- ============================================================
-- 2. 产品表 — 丰富扫描目标，供数据爆破演示更多结果
-- ============================================================

DROP TABLE IF EXISTS products;

CREATE TABLE products (
    id          INT PRIMARY KEY AUTO_INCREMENT   COMMENT '产品ID',
    name        VARCHAR(200) NOT NULL            COMMENT '产品名称',
    price       DECIMAL(10,2) DEFAULT 0.00       COMMENT '价格',
    category    VARCHAR(50)  DEFAULT NULL        COMMENT '分类',
    stock       INT          DEFAULT 0           COMMENT '库存数量',
    description TEXT                             COMMENT '产品描述',
    created_at  DATETIME     DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='产品表';

INSERT INTO products (name, price, category, stock, description) VALUES
    ('ThinkPad X1 Carbon',      8999.00,  '笔记本电脑', 50,  '联想商务旗舰，14英寸轻薄本'),
    ('MacBook Pro 14',          14999.00, '笔记本电脑', 30,  '苹果专业级笔记本，M3 Pro 芯片'),
    ('iPhone 15 Pro',           8999.00,  '手机',       100, '苹果旗舰手机，钛金属设计'),
    ('Samsung Galaxy S24 Ultra',9999.00,  '手机',       80,  '三星年度旗舰，AI 智能体验'),
    ('Sony WH-1000XM5',         2299.00,  '耳机',       200, '索尼旗舰降噪耳机'),
    ('NVIDIA RTX 4090',         12999.00, '显卡',       15,  'NVIDIA 旗舰游戏显卡'),
    ('Dell UltraSharp U2723QE', 3999.00,  '显示器',     40,  '戴尔专业 4K 显示器'),
    ('Logitech MX Master 3S',   699.00,   '外设',       120, '罗技旗舰办公鼠标');

-- ============================================================
-- 3. 系统配置表 — 模拟敏感的配置信息存储
-- ============================================================

DROP TABLE IF EXISTS system_config;

CREATE TABLE system_config (
    id          INT PRIMARY KEY AUTO_INCREMENT   COMMENT '配置ID',
    config_key  VARCHAR(100) NOT NULL UNIQUE     COMMENT '配置键',
    config_value TEXT                            COMMENT '配置值',
    description VARCHAR(255) DEFAULT NULL        COMMENT '配置说明',
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='系统配置表';

INSERT INTO system_config (config_key, config_value, description) VALUES
    ('site_name',        'Internal Admin Panel', '站点名称'),
    ('admin_email',      'root@internal.com',    '管理员邮箱'),
    ('secret_key',       'a3f8b2c1d4e5f6a7b8c9', '应用密钥'),
    ('api_endpoint',     'https://api.internal.com/v2', 'API 地址'),
    ('db_backup_path',   '/var/backups/mysql/',  '数据库备份路径'),
    ('log_level',        'DEBUG',                '日志级别'),
    ('maintenance_mode', 'false',                '维护模式开关');

-- ============================================================
-- 验证数据
-- ============================================================
SELECT 'users 表:'        AS '检查项', COUNT(*) AS '记录数' FROM users
UNION ALL
SELECT 'products 表:',       COUNT(*) FROM products
UNION ALL
SELECT 'system_config 表:',  COUNT(*) FROM system_config;

-- 初始化完成
SELECT '✅ 数据库初始化完成！' AS '状态';
