# JWT Authentication Demo

## Mô tả
Dự án này minh họa cách xác thực người dùng sử dụng JSON Web Token (JWT) với thuật toán RSA256.

## Cài đặt
Trước khi chạy dự án, bạn cần cài đặt các package cần thiết:
```sh
npm install
```

## Tạo cặp khóa RSA256
Dễ tạo cặp khóa cho JWT, chạy các lệnh sau:
```sh
openssl genrsa -out jwtRSA256-private.pem 2048
openssl rsa -in jwtRSA256-private.pem -pubout -outform PEM -out jwtRSA256-public.pem
```

- **jwtRSA256-private.pem**: Khóa private để ký JWT.
- **jwtRSA256-public.pem**: Khóa public để xác minh JWT.

## Chạy ứng dụng
Sử dụng **nodemon** để chạy và reload tự động khi code thay đổi:
```sh
nodemon app.js
```

## API Endpoints

### 1. Đăng ký (Register)
```http
POST /register
```
- **Body:**
```json
{
  "username": "example",
  "password": "password123"
}
```
- **Response:**
```json
{
  "message": "User registered successfully"
}
```

### 2. Đăng nhập (Login)
```http
POST /login
```
- **Body:**
```json
{
  "username": "example",
  "password": "password123",
  "role": "<admin/user>
}
```
- **Response:**
```json
{
  "token": "<JWT Token>"
}
```

### 3. Truy cập tài nguyên bảo vệ (Protected Route)
```http
GET /protected, admin, user
```
- **Headers:**
```json
{
  "Authorization": "Bearer <JWT Token>"
}
```
- **Response:**
```json
{
  "message": "Access granted"
}
```

## Cấu hình
Bạn có thể chỉnh sửa các biến môi trường trong file `.env`:

## Công nghệ sử dụng
- Node.js
- Express.js
- jsonwebtoken (JWT)
- OpenSSL (tạo khóa RSA)

## Giấy phép
MIT License