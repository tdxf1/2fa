## ⚙️ 配置说明
创建 KV 命名空间 ：USER_DATA
### 必需的环境变量

| 变量名             | 描述           | 示例                           |
| :----------------- | :------------- | :----------------------------- |
| `OAUTH_CLIENT_ID`  | OAuth 客户端 ID | `your_oauth_client_id`         |
| `OAUTH_CLIENT_SECRET` | OAuth 客户端密钥 | `your_oauth_client_secret`     |
| `OAUTH_BASE_URL`   | OAuth 服务器地址 | `https://oauth.example.com`    |
| `OAUTH_REDIRECT_URI` | OAuth 回调地址 | `https://your-app.workers.dev/api/oauth/callback` |
| `OAUTH_ID`         | 授权用户 ID    | `12345`                        |
| `JWT_SECRET`       | JWT 签名密钥   | `your_strong_jwt_secret`       |
| `ENCRYPTION_KEY`   | 数据加密密钥   | `your_encryption_key`          |

### 可选的环境变量

| 变量名           | 描述         | 默认值 |
| :--------------- | :----------- | :----- |
| `ALLOWED_ORIGINS` | 允许的跨域来源 | `*`    |
