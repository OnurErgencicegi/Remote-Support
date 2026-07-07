# Auth Server

Sade kullanıcı kayıt/giriş API'si. RustDesk launcher uygulaması için
kullanıcı doğrulama katmanı sağlar. WebRTC/socket.io içermez — sadece
kullanıcı hesabı yönetimi (email+parola, tier bilgisi).

## Kurulum (droplette veya yerelde)

```bash
npm install
```

## Ortam değişkenleri (ÖNEMLİ)

Production'da mutlaka bir JWT_SECRET tanımlayın:

```bash
export JWT_SECRET="cok-uzun-rastgele-guvenli-bir-metin"
```

pm2 ile kalıcı başlatma:
```bash
JWT_SECRET="cok-uzun-rastgele-guvenli-metin" pm2 start server.js --name auth-server
pm2 save
```

## Endpoint'ler

### POST /auth/register
```json
{ "email": "kullanici@ornek.com", "password": "en-az-6-karakter" }
```
Döner: `{ token, user: { email, tier } }`

### POST /auth/login
```json
{ "email": "kullanici@ornek.com", "password": "sifre" }
```
Döner: `{ token, user: { email, tier } }`

### GET /auth/me
Header: `Authorization: Bearer <token>`
Döner: `{ email, tier, rustdeskId, isActive, createdAt }`

### POST /auth/me/rustdesk-id
Header: `Authorization: Bearer <token>`
```json
{ "rustdeskId": "123456789" }
```
Kullanıcının RustDesk ID'sini kendi hesabına bağlar (launcher, RustDesk
client'ın ürettiği ID'yi öğrenip bunu çağırarak sunucuya kaydedebilir).

## Test (curl)

```bash
curl -X POST http://localhost:4000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"sifre123"}'
```

## Sıradaki adımlar (henüz yapılmadı)

- Tier bazlı limit mantığı (örn. free kullanıcı kaç cihaza bağlanabilir)
- Launcher (Electron) uygulaması: login ekranı + RustDesk.exe'yi başlatma
- Nginx ile bu API'yi bir alt domain/path üzerinden HTTPS ile yayınlama
